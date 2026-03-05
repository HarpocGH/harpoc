import { createServer } from "node:http";
import type { Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { HttpInjector } from "./http-injector.js";

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", `http://localhost`);

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
});
