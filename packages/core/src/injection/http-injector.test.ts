import { createServer } from "node:http";
import type { Server } from "node:http";
import { ErrorCode } from "@harpoc/shared";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { HttpInjector } from "./http-injector.js";

let server: Server;
let baseUrl: string;
const requestPaths: string[] = [];

async function rejectionOf(promise: Promise<unknown>): Promise<Error> {
  const err = await promise.then(
    () => undefined,
    (e: unknown) => e as Error,
  );
  if (err === undefined) throw new Error("expected the call to reject");
  return err;
}

beforeAll(async () => {
  server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", `http://localhost`);
    requestPaths.push(url.pathname);

    if (url.pathname === "/echo") {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        const auth = req.headers["authorization"] ?? "";
        const custom = req.headers["x-api-key"] ?? "";
        const queryKey = url.searchParams.get("api_key") ?? "";
        const body = chunks.length > 0 ? Buffer.concat(chunks).toString("utf8") : undefined;
        const contentType = req.headers["content-type"] ?? "";

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            authorization: auth,
            custom_header: custom,
            query_key: queryKey,
            method: req.method,
            body,
            content_type: contentType,
          }),
        );
      });
      return;
    }

    if (url.pathname === "/status") {
      const code = parseInt(url.searchParams.get("code") ?? "200", 10);
      if (code === 204) {
        res.writeHead(204);
        res.end();
      } else {
        res.writeHead(code, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: code }));
      }
      return;
    }

    if (url.pathname === "/redirect") {
      res.writeHead(302, {
        Location: `http://localhost:${(server.address() as { port: number }).port}/echo`,
      });
      res.end();
      return;
    }

    if (url.pathname === "/redirect-same") {
      res.writeHead(302, {
        Location: `http://127.0.0.1:${(server.address() as { port: number }).port}/echo`,
      });
      res.end();
      return;
    }

    if (url.pathname === "/redirect-private") {
      res.writeHead(302, { Location: "https://10.0.0.1/steal" });
      res.end();
      return;
    }

    // Cross-origin hop that carries the incoming query string along, the way a
    // real endpoint preserving its parameters across a redirect would. Without
    // it the injected query parameter is dropped by the hop's own Location and
    // the strip at http-injector.ts:353 is never exercised (T1).
    if (url.pathname === "/redirect-keep-query") {
      const port = (server.address() as { port: number }).port;
      res.writeHead(302, {
        Location: `http://localhost:${port}/echo?${url.searchParams.toString()}`,
      });
      res.end();
      return;
    }

    // Hostile endpoint: reflects the credential it just received back into the
    // Location header of a hop it knows the vault will refuse (H2).
    if (url.pathname === "/redirect-echo-credential") {
      const auth = String(req.headers["authorization"] ?? "").replace(/^Bearer\s+/i, "");
      const custom = String(req.headers["x-api-key"] ?? "");
      const stolen = auth || custom || url.searchParams.get("api_key") || "nothing";
      res.writeHead(302, { Location: `https://10.0.0.1/leak/${encodeURIComponent(stolen)}` });
      res.end();
      return;
    }

    // Reflects the credential into the *hostname* of the refused hop, where
    // reporting the origin alone does not remove it — only redaction does.
    if (url.pathname === "/redirect-echo-credential-host") {
      const auth = String(req.headers["authorization"] ?? "").replace(/^Bearer\s+/i, "");
      res.writeHead(302, { Location: `https://${auth.toLowerCase()}.invalid/` });
      res.end();
      return;
    }

    // Same, but the refused hop is a non-allowlisted public host rather than a
    // private one — exercises the url_allowlist branch.
    if (url.pathname === "/redirect-echo-credential-allowlist") {
      const auth = String(req.headers["authorization"] ?? "").replace(/^Bearer\s+/i, "");
      res.writeHead(302, { Location: `https://8.8.8.8/leak/${encodeURIComponent(auth)}` });
      res.end();
      return;
    }

    // Same-origin redirect chain: /chain/N hops down to /chain/1, which points
    // at /chain-end. MAX_REDIRECTS is 5, so /chain/6 exhausts the budget and the
    // hop out of /chain/1 is refused before it executes.
    const chainStep = /^\/chain\/(\d+)$/.exec(url.pathname);
    if (chainStep) {
      const step = parseInt(chainStep[1] as string, 10);
      const next = step > 1 ? `/chain/${String(step - 1)}` : "/chain-end";
      res.writeHead(302, {
        Location: `http://127.0.0.1:${(server.address() as { port: number }).port}${next}`,
      });
      res.end();
      return;
    }

    if (url.pathname === "/chain-end") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ chain: "end" }));
      return;
    }

    if (url.pathname === "/slow") {
      // Don't respond — simulate timeout
      return;
    }

    res.writeHead(404);
    res.end("Not Found");
  });

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = server.address() as { port: number };
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(() => {
  server.close();
});

describe("HttpInjector", () => {
  const injector = new HttpInjector(null);

  describe("bearer injection", () => {
    it("injects Bearer token in Authorization header", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/echo` },
        new Uint8Array(Buffer.from("my-token")),
        { type: "bearer" },
      );

      expect(response.status).toBe(200);
      const body = JSON.parse(response.body ?? "{}") as Record<string, string>;
      expect(body.authorization).toBe("Bearer my-token");
    });
  });

  describe("header injection", () => {
    it("injects value in custom header", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/echo` },
        new Uint8Array(Buffer.from("key-123")),
        { type: "header", header_name: "X-Api-Key" },
      );

      expect(response.status).toBe(200);
      const body = JSON.parse(response.body ?? "{}") as Record<string, string>;
      expect(body.custom_header).toBe("key-123");
    });
  });

  describe("query injection", () => {
    it("injects value as query parameter", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/echo` },
        new Uint8Array(Buffer.from("query-val")),
        { type: "query", query_param: "api_key" },
      );

      expect(response.status).toBe(200);
      const body = JSON.parse(response.body ?? "{}") as Record<string, string>;
      expect(body.query_key).toBe("query-val");
    });
  });

  describe("basic_auth injection", () => {
    it("injects Basic auth header", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/echo` },
        new Uint8Array(Buffer.from("user:pass")),
        { type: "basic_auth" },
      );

      expect(response.status).toBe(200);
      const body = JSON.parse(response.body ?? "{}") as Record<string, string>;
      expect(body.authorization).toBe(`Basic ${Buffer.from("user:pass").toString("base64")}`);
    });
  });

  describe("timeout handling", () => {
    it("returns TIMEOUT error for slow server", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/slow`, timeoutMs: 500 },
        new Uint8Array(Buffer.from("val")),
        { type: "bearer" },
      );

      expect(response.status).toBeNull();
      expect(response.error).toBe("TIMEOUT");
    });
  });

  describe("redirect handling", () => {
    it("follows same-origin redirects by default", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/redirect` },
        new Uint8Array(Buffer.from("token")),
        { type: "bearer" },
        "same-origin",
      );

      expect(response.status).toBe(200);
    });

    it("returns redirect response with none policy", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/redirect` },
        new Uint8Array(Buffer.from("token")),
        { type: "bearer" },
        "none",
      );

      expect(response.status).toBe(302);
    });

    it("rejects a redirect to a private-network target (per-hop SSRF re-validation)", async () => {
      const before = requestPaths.length;
      await expect(
        injector.executeWithSecret(
          { method: "GET", url: `${baseUrl}/redirect-private` },
          new Uint8Array(Buffer.from("token")),
          { type: "bearer" },
          "any",
        ),
      ).rejects.toMatchObject({ code: ErrorCode.REDIRECT_POLICY_VIOLATION });
      // Only the redirecting response itself was fetched — the private hop never executed.
      expect(requestPaths.slice(before)).toEqual(["/redirect-private"]);
    });

    // H2: the refused hop is authored by the endpoint that just received the
    // credential, so its URL must never reach the thrown message — that message
    // becomes the MCP tool result text and the REST error body.
    describe("refusal messages never carry the credential (H2)", () => {
      const CREDENTIAL = "sk-live-h2-9f3a2b7c1d4e5f60";

      it("bearer: SSRF-refused hop reflecting the token", async () => {
        const err = await rejectionOf(
          injector.executeWithSecret(
            { method: "GET", url: `${baseUrl}/redirect-echo-credential` },
            new Uint8Array(Buffer.from(CREDENTIAL)),
            { type: "bearer" },
            "any",
          ),
        );
        expect(err).toMatchObject({ code: ErrorCode.REDIRECT_POLICY_VIOLATION });
        expect(err.message).not.toContain(CREDENTIAL);
        expect(err.message).not.toContain(encodeURIComponent(CREDENTIAL));
      });

      it("header injection: SSRF-refused hop reflecting the header value", async () => {
        const err = await rejectionOf(
          injector.executeWithSecret(
            { method: "GET", url: `${baseUrl}/redirect-echo-credential` },
            new Uint8Array(Buffer.from(CREDENTIAL)),
            { type: "header", header_name: "X-Api-Key" },
            "any",
          ),
        );
        expect(err.message).not.toContain(CREDENTIAL);
      });

      it("allowlist-refused hop reflecting the token", async () => {
        const err = await rejectionOf(
          injector.executeWithSecret(
            {
              method: "GET",
              url: `${baseUrl}/redirect-echo-credential-allowlist`,
              urlAllowlist: [`${baseUrl}/*`],
            },
            new Uint8Array(Buffer.from(CREDENTIAL)),
            { type: "bearer" },
            "any",
          ),
        );
        expect(err).toMatchObject({ code: ErrorCode.URL_NOT_ALLOWED });
        expect(err.message).not.toContain(CREDENTIAL);
      });

      it("status_only does not help — the leak was on the throw path", async () => {
        const err = await rejectionOf(
          injector.executeWithSecret(
            {
              method: "GET",
              url: `${baseUrl}/redirect-echo-credential`,
              responseMode: "status_only",
            },
            new Uint8Array(Buffer.from(CREDENTIAL)),
            { type: "bearer" },
            "any",
          ),
        );
        expect(err.message).not.toContain(CREDENTIAL);
      });

      // Pins guard 1 (origin only, never the full URL) independently of the
      // redaction backstop: with the whole URL interpolated the path survives
      // even though the credential inside it would be redacted.
      it("reports the origin without the endpoint-authored path", async () => {
        const err = await rejectionOf(
          injector.executeWithSecret(
            { method: "GET", url: `${baseUrl}/redirect-echo-credential` },
            new Uint8Array(Buffer.from(CREDENTIAL)),
            { type: "bearer" },
            "any",
          ),
        );
        expect(err.message).not.toContain("/leak/");
      });

      // Pins guard 2 (the redaction backstop) independently of guard 1: a
      // credential reflected into the hostname is part of the origin itself.
      it("redacts a credential reflected into the refused hop's hostname", async () => {
        const lower = CREDENTIAL.toLowerCase();
        const err = await rejectionOf(
          injector.executeWithSecret(
            { method: "GET", url: `${baseUrl}/redirect-echo-credential-host` },
            new Uint8Array(Buffer.from(lower)),
            { type: "bearer" },
            "any",
          ),
        );
        expect(err.message).not.toContain(lower);
      });

      it("still names the refused origin, so the refusal stays diagnosable", async () => {
        const err = await rejectionOf(
          injector.executeWithSecret(
            { method: "GET", url: `${baseUrl}/redirect-private` },
            new Uint8Array(Buffer.from(CREDENTIAL)),
            { type: "bearer" },
            "any",
          ),
        );
        expect(err.message).toContain("https://10.0.0.1");
      });
    });
  });

  describe("redirect URL-allowlist enforcement (thesis §4.5.2)", () => {
    const port = () => new URL(baseUrl).port;

    it("blocks a credential-bearing cross-origin redirect to a non-allowlisted target (any mode)", async () => {
      const before = requestPaths.length;
      await expect(
        injector.executeWithSecret(
          { method: "GET", url: `${baseUrl}/redirect`, urlAllowlist: [`${baseUrl}/*`] },
          new Uint8Array(Buffer.from("token")),
          { type: "bearer" },
          "any",
        ),
      ).rejects.toMatchObject({ code: ErrorCode.URL_NOT_ALLOWED });
      // Only the redirect response itself was fetched — the hop never executed.
      expect(requestPaths.slice(before)).toEqual(["/redirect"]);
    });

    it("blocks a non-allowlisted cross-origin hop even when credentials would be stripped (same-origin mode)", async () => {
      await expect(
        injector.executeWithSecret(
          { method: "GET", url: `${baseUrl}/redirect`, urlAllowlist: [`${baseUrl}/*`] },
          new Uint8Array(Buffer.from("token")),
          { type: "bearer" },
          "same-origin",
        ),
      ).rejects.toMatchObject({ code: ErrorCode.URL_NOT_ALLOWED });
    });

    it("follows a redirect whose hop matches the allowlist", async () => {
      const response = await injector.executeWithSecret(
        {
          method: "GET",
          url: `${baseUrl}/redirect`,
          urlAllowlist: [`${baseUrl}/*`, `http://localhost:${port()}/*`],
        },
        new Uint8Array(Buffer.from("token")),
        { type: "bearer" },
        "any",
      );

      expect(response.status).toBe(200);
      const body = JSON.parse(response.body ?? "{}") as Record<string, string>;
      expect(body.authorization).toBe("Bearer token");
    });

    it("enforces path patterns per hop even on same-origin redirects", async () => {
      await expect(
        injector.executeWithSecret(
          {
            method: "GET",
            url: `${baseUrl}/redirect-same`,
            urlAllowlist: [`${baseUrl}/redirect-same*`],
          },
          new Uint8Array(Buffer.from("token")),
          { type: "bearer" },
          "any",
        ),
      ).rejects.toMatchObject({ code: ErrorCode.URL_NOT_ALLOWED });
    });

    it("leaves hops unconstrained when no allowlist is configured", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/redirect` },
        new Uint8Array(Buffer.from("token")),
        { type: "bearer" },
        "any",
      );

      expect(response.status).toBe(200);
    });
  });

  /**
   * T1: the strip itself was pinned only by the `redirect_warning` string, so
   * deleting all three statements while keeping the assignment left the suite
   * green while the wire delivered the credential to the cross-origin hop.
   * These assertions read what the second server actually received.
   */
  describe("cross-origin redirects strip the injected credential (same-origin mode)", () => {
    const CREDENTIAL = "sk-live-t1-4c8e1a90fb27d635";
    const echoed = (response: { body?: string }) =>
      JSON.parse(response.body ?? "{}") as Record<string, string>;

    it("the Authorization header does not reach the cross-origin hop", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/redirect` },
        new Uint8Array(Buffer.from(CREDENTIAL)),
        { type: "bearer" },
        "same-origin",
      );

      expect(response.status).toBe(200);
      expect(echoed(response).authorization).toBe("");
      expect(response.body).not.toContain(CREDENTIAL);
      expect(response.redirect_warning).toContain("credentials stripped");
    });

    it("the injected custom header does not reach the cross-origin hop", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/redirect` },
        new Uint8Array(Buffer.from(CREDENTIAL)),
        { type: "header", header_name: "X-Api-Key" },
        "same-origin",
      );

      expect(response.status).toBe(200);
      expect(echoed(response).custom_header).toBe("");
      expect(response.body).not.toContain(CREDENTIAL);
    });

    // basic_auth shares the Authorization header with bearer but encodes the
    // value, so a redaction-shaped defence would not catch it — only the strip.
    it("basic_auth credentials do not reach the cross-origin hop", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/redirect` },
        new Uint8Array(Buffer.from(`user:${CREDENTIAL}`)),
        { type: "basic_auth" },
        "same-origin",
      );

      expect(echoed(response).authorization).toBe("");
      expect(response.body).not.toContain(Buffer.from(`user:${CREDENTIAL}`).toString("base64"));
    });

    it("the injected query parameter does not survive the cross-origin hop", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/redirect-keep-query` },
        new Uint8Array(Buffer.from(CREDENTIAL)),
        { type: "query", query_param: "api_key" },
        "same-origin",
      );

      expect(response.status).toBe(200);
      expect(echoed(response).query_key).toBe("");
      expect(response.body).not.toContain(CREDENTIAL);
    });

    // Controls: stripping is scoped to cross-origin hops under same-origin
    // policy — it must not fire on a same-origin hop, and `any` is the mode
    // that deliberately carries the credential across origins.
    it("control: a same-origin hop still receives the credential", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/redirect-same` },
        new Uint8Array(Buffer.from(CREDENTIAL)),
        { type: "bearer" },
        "same-origin",
      );

      expect(echoed(response).authorization).toBe(`Bearer ${CREDENTIAL}`);
      expect(response.redirect_warning).toBeUndefined();
    });

    it("control: `any` carries the credential across origins by design", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/redirect` },
        new Uint8Array(Buffer.from(CREDENTIAL)),
        { type: "bearer" },
        "any",
      );

      expect(echoed(response).authorization).toBe(`Bearer ${CREDENTIAL}`);
    });
  });

  describe("response mode shaping", () => {
    it("status_only returns the status without body or headers", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/echo`, responseMode: "status_only" },
        new Uint8Array(Buffer.from("shape-tok")),
        { type: "bearer" },
      );

      expect(response.status).toBe(200);
      expect(response.body).toBeUndefined();
      expect(response.headers).toBeUndefined();
      expect(response.error).toBeUndefined();
    });

    it("status_only returns only allowlisted headers, case-insensitively", async () => {
      const response = await injector.executeWithSecret(
        {
          method: "GET",
          url: `${baseUrl}/echo`,
          responseMode: "status_only",
          responseHeaderAllowlist: ["CONTENT-TYPE"],
        },
        new Uint8Array(Buffer.from("shape-tok")),
        { type: "bearer" },
      );

      expect(response.headers).toEqual({ "content-type": "application/json" });
      expect(response.body).toBeUndefined();
    });

    it("status_only shapes a 3xx returned under the none redirect policy", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/redirect`, responseMode: "status_only" },
        new Uint8Array(Buffer.from("shape-tok")),
        { type: "bearer" },
        "none",
      );

      expect(response.status).toBe(302);
      expect(response.body).toBeUndefined();
      expect(response.headers).toBeUndefined();
    });

    it("status_only preserves redirect_warning across a followed cross-origin redirect", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/redirect`, responseMode: "status_only" },
        new Uint8Array(Buffer.from("shape-tok")),
        { type: "bearer" },
        "same-origin",
      );

      expect(response.status).toBe(200);
      expect(response.body).toBeUndefined();
      expect(response.redirect_warning).toContain("credentials stripped");
    });

    it("status_only handles a 204 response without a body stream", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/status?code=204`, responseMode: "status_only" },
        new Uint8Array(Buffer.from("shape-tok")),
        { type: "bearer" },
      );

      expect(response.status).toBe(204);
      expect(response.body).toBeUndefined();
    });

    it("status_only preserves the error field on failure", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/slow`, timeoutMs: 500, responseMode: "status_only" },
        new Uint8Array(Buffer.from("shape-tok")),
        { type: "bearer" },
      );

      expect(response.status).toBeNull();
      expect(response.error).toBe("TIMEOUT");
    });

    it.each(["filtered", "full"] as const)(
      "%s returns body and headers at the injector layer",
      async (mode) => {
        const response = await injector.executeWithSecret(
          { method: "GET", url: `${baseUrl}/echo`, responseMode: mode },
          new Uint8Array(Buffer.from("shape-tok")),
          { type: "bearer" },
        );

        expect(response.status).toBe(200);
        expect(response.body).toBeDefined();
        expect(response.headers).toBeDefined();
      },
    );
  });

  describe("URL validation", () => {
    it("rejects HTTP for non-loopback", async () => {
      await expect(
        injector.executeWithSecret(
          { method: "GET", url: "http://example.com/api" },
          new Uint8Array(Buffer.from("val")),
          { type: "bearer" },
        ),
      ).rejects.toThrow("loopback");
    });

    it("rejects SSRF targets", async () => {
      await expect(
        injector.executeWithSecret(
          { method: "GET", url: "https://10.0.0.1/api" },
          new Uint8Array(Buffer.from("val")),
          { type: "bearer" },
        ),
      ).rejects.toThrow("SSRF");
    });
  });

  describe("error classification", () => {
    it("returns DNS_RESOLUTION_FAILED for unknown hosts", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: "https://this-host-does-not-exist-xyz123.invalid/api" },
        new Uint8Array(Buffer.from("val")),
        { type: "bearer" },
      );

      expect(response.status).toBeNull();
      expect(response.error).toBe("DNS_RESOLUTION_FAILED");
    });

    it("returns CONNECTION_REFUSED for refused connections", async () => {
      // Port 2 is almost certainly not listening
      const response = await injector.executeWithSecret(
        { method: "GET", url: "http://127.0.0.1:2/api", timeoutMs: 5000 },
        new Uint8Array(Buffer.from("val")),
        { type: "bearer" },
      );

      expect(response.status).toBeNull();
      expect(["CONNECTION_REFUSED", "TIMEOUT"]).toContain(response.error);
    });
  });

  describe("POST/PUT/PATCH with body and injection", () => {
    it("POST with JSON body and bearer injection", async () => {
      const response = await injector.executeWithSecret(
        {
          method: "POST",
          url: `${baseUrl}/echo`,
          body: JSON.stringify({ key: "value" }),
          headers: { "Content-Type": "application/json" },
        },
        new Uint8Array(Buffer.from("post-token")),
        { type: "bearer" },
      );

      expect(response.status).toBe(200);
      const body = JSON.parse(response.body ?? "{}") as Record<string, string>;
      expect(body.authorization).toBe("Bearer post-token");
      expect(body.body).toBe(JSON.stringify({ key: "value" }));
      expect(body.method).toBe("POST");
    });

    it("PUT with body and header injection", async () => {
      const response = await injector.executeWithSecret(
        {
          method: "PUT",
          url: `${baseUrl}/echo`,
          body: "put-body-data",
        },
        new Uint8Array(Buffer.from("put-key")),
        { type: "header", header_name: "X-Api-Key" },
      );

      expect(response.status).toBe(200);
      const body = JSON.parse(response.body ?? "{}") as Record<string, string>;
      expect(body.custom_header).toBe("put-key");
      expect(body.body).toBe("put-body-data");
      expect(body.method).toBe("PUT");
    });

    it("POST with body and query injection", async () => {
      const response = await injector.executeWithSecret(
        {
          method: "POST",
          url: `${baseUrl}/echo`,
          body: "query-body",
        },
        new Uint8Array(Buffer.from("query-val")),
        { type: "query", query_param: "api_key" },
      );

      expect(response.status).toBe(200);
      const body = JSON.parse(response.body ?? "{}") as Record<string, string>;
      expect(body.query_key).toBe("query-val");
      expect(body.body).toBe("query-body");
      expect(body.method).toBe("POST");
    });

    it("PATCH with body and basic_auth injection", async () => {
      const response = await injector.executeWithSecret(
        {
          method: "PATCH",
          url: `${baseUrl}/echo`,
          body: "patch-data",
        },
        new Uint8Array(Buffer.from("user:pass")),
        { type: "basic_auth" },
      );

      expect(response.status).toBe(200);
      const body = JSON.parse(response.body ?? "{}") as Record<string, string>;
      expect(body.authorization).toBe(`Basic ${Buffer.from("user:pass").toString("base64")}`);
      expect(body.body).toBe("patch-data");
      expect(body.method).toBe("PATCH");
    });
  });

  describe("error status codes", () => {
    it("captures 400 Bad Request response", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/status?code=400` },
        new Uint8Array(Buffer.from("val")),
        { type: "bearer" },
      );

      expect(response.status).toBe(400);
      const body = JSON.parse(response.body ?? "{}") as Record<string, number>;
      expect(body.status).toBe(400);
    });

    it("captures 500 Internal Server Error response", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/status?code=500` },
        new Uint8Array(Buffer.from("val")),
        { type: "bearer" },
      );

      expect(response.status).toBe(500);
      const body = JSON.parse(response.body ?? "{}") as Record<string, number>;
      expect(body.status).toBe(500);
    });

    it("captures 204 No Content with empty body", async () => {
      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/status?code=204` },
        new Uint8Array(Buffer.from("val")),
        { type: "bearer" },
      );

      expect(response.status).toBe(204);
      expect(response.body === "" || response.body === undefined).toBe(true);
    });
  });

  /**
   * The redirect ceiling (`MAX_REDIRECTS = 5`) had no test: the branch could be
   * deleted and the suite stayed green. The request log is what pins it — the
   * refusal must land *before* the sixth hop reaches the wire.
   */
  describe("redirect ceiling", () => {
    it("refuses the sixth hop of a same-origin chain and never executes it", async () => {
      const before = requestPaths.length;

      await expect(
        injector.executeWithSecret(
          { method: "GET", url: `${baseUrl}/chain/6` },
          new Uint8Array(Buffer.from("token")),
          { type: "bearer" },
          "same-origin",
        ),
      ).rejects.toMatchObject({
        code: ErrorCode.REDIRECT_POLICY_VIOLATION,
        message: "Too many redirects",
      });

      // Five hops followed, the sixth refused: /chain-end never appears.
      expect(requestPaths.slice(before)).toEqual([
        "/chain/6",
        "/chain/5",
        "/chain/4",
        "/chain/3",
        "/chain/2",
        "/chain/1",
      ]);
    });

    it("control: a five-redirect chain still reaches its target", async () => {
      const before = requestPaths.length;

      const response = await injector.executeWithSecret(
        { method: "GET", url: `${baseUrl}/chain/5` },
        new Uint8Array(Buffer.from("token")),
        { type: "bearer" },
        "same-origin",
      );

      expect(response.status).toBe(200);
      expect(requestPaths.slice(before)).toEqual([
        "/chain/5",
        "/chain/4",
        "/chain/3",
        "/chain/2",
        "/chain/1",
        "/chain-end",
      ]);
    });
  });
});
