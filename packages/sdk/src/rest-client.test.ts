import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { RestClient } from "./rest-client.js";

const BASE_URL = "http://localhost:3000";
const TOKEN = "test-jwt-token";

let client: RestClient;
let fetchSpy: ReturnType<typeof vi.fn>;

function mockFetchResponse(data: unknown, status = 200) {
  fetchSpy.mockResolvedValueOnce({
    ok: status >= 200 && status < 300,
    status,
    json: async () => (status >= 200 && status < 300 ? { data } : data),
  });
}

beforeEach(() => {
  fetchSpy = vi.fn();
  vi.stubGlobal("fetch", fetchSpy);
  client = new RestClient({ baseUrl: BASE_URL, token: TOKEN });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("RestClient", () => {
  describe("listSecrets", () => {
    it("sends GET /api/v1/secrets", async () => {
      mockFetchResponse([]);
      const result = await client.listSecrets();

      expect(result).toEqual([]);
      expect(fetchSpy).toHaveBeenCalledWith(
        `${BASE_URL}/api/v1/secrets`,
        expect.objectContaining({ method: "GET" }),
      );
    });

    it("includes project query param", async () => {
      mockFetchResponse([]);
      await client.listSecrets("myproj");

      expect(fetchSpy).toHaveBeenCalledWith(
        `${BASE_URL}/api/v1/secrets?project=myproj`,
        expect.anything(),
      );
    });
  });

  describe("getSecretInfo", () => {
    it("sends GET /api/v1/secrets/:handle", async () => {
      const info = { handle: "secret://key", name: "key" };
      mockFetchResponse(info);
      const result = await client.getSecretInfo("secret://key");

      expect(result).toEqual(info);
      expect(fetchSpy).toHaveBeenCalledWith(
        `${BASE_URL}/api/v1/secrets/key`,
        expect.anything(),
      );
    });

    it("encodes project/name handles", async () => {
      mockFetchResponse({});
      await client.getSecretInfo("secret://proj/key");

      expect(fetchSpy).toHaveBeenCalledWith(
        `${BASE_URL}/api/v1/secrets/proj%2Fkey`,
        expect.anything(),
      );
    });
  });

  describe("getSecretValue", () => {
    it("returns Uint8Array from base64 response", async () => {
      const b64 = Buffer.from("secret-val").toString("base64");
      mockFetchResponse({ value: b64 });
      const result = await client.getSecretValue("secret://key");

      expect(Buffer.from(result).toString()).toBe("secret-val");
    });
  });

  describe("createSecret", () => {
    it("sends POST with body", async () => {
      const response = { handle: "secret://k", status: "created", message: "OK" };
      mockFetchResponse(response);

      const result = await client.createSecret({ name: "k", type: "api_key" });
      expect(result).toEqual(response);

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/secrets`);
      expect(call[1].method).toBe("POST");
      const body = JSON.parse(call[1].body as string);
      expect(body.name).toBe("k");
    });

    it("encodes value as base64", async () => {
      mockFetchResponse({});
      await client.createSecret({
        name: "k",
        type: "api_key",
        value: new Uint8Array([1, 2, 3]),
      });

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      const body = JSON.parse(call[1].body as string);
      expect(body.value).toBe(Buffer.from([1, 2, 3]).toString("base64"));
    });
  });

  describe("rotateSecret", () => {
    it("sends POST with base64 value", async () => {
      mockFetchResponse({ rotated: true });
      await client.rotateSecret("secret://k", new Uint8Array([4, 5, 6]));

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toContain("/api/v1/secrets/k/rotate");
      const body = JSON.parse(call[1].body as string);
      expect(body.value).toBe(Buffer.from([4, 5, 6]).toString("base64"));
    });
  });

  describe("revokeSecret", () => {
    it("sends DELETE with confirm=true", async () => {
      mockFetchResponse({ revoked: true });
      await client.revokeSecret("secret://k");

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toContain("/api/v1/secrets/k?confirm=true");
      expect(call[1].method).toBe("DELETE");
    });
  });

  describe("useSecret", () => {
    it("sends use request with proper field mapping", async () => {
      mockFetchResponse({ status: 200, body: "ok" });
      await client.useSecret("secret://k", {
        request: { method: "GET", url: "https://api.example.com", timeoutMs: 5000 },
        injection: { type: "bearer" },
        followRedirects: "none",
      });

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      const body = JSON.parse(call[1].body as string);
      expect(body.request.timeout_ms).toBe(5000);
      expect(body.follow_redirects).toBe("none");
    });
  });

  describe("policies", () => {
    it("grantPolicy sends POST", async () => {
      mockFetchResponse({ id: "p1" });
      await client.grantPolicy("secret://k", {
        principalType: "agent",
        principalId: "a1",
        permissions: ["read"],
      });

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toContain("/api/v1/secrets/k/policies");
      const body = JSON.parse(call[1].body as string);
      expect(body.principal_type).toBe("agent");
    });

    it("revokePolicy sends DELETE", async () => {
      mockFetchResponse({ revoked: true });
      await client.revokePolicy("secret://k", "p1");

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toContain("/api/v1/secrets/k/policies/p1");
      expect(call[1].method).toBe("DELETE");
    });

    it("listPolicies sends GET", async () => {
      mockFetchResponse([]);
      await client.listPolicies("secret://k");

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toContain("/api/v1/secrets/k/policies");
      expect(call[1].method).toBe("GET");
    });
  });

  describe("queryAudit", () => {
    it("sends GET with query params", async () => {
      mockFetchResponse([]);
      await client.queryAudit({
        secretId: "uuid-1",
        eventType: "secret.read",
        limit: 10,
      });

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toContain("secret_id=uuid-1");
      expect(call[0]).toContain("event_type=secret.read");
      expect(call[0]).toContain("limit=10");
    });

    it("sends GET without params when options omitted", async () => {
      mockFetchResponse([]);
      await client.queryAudit();

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(call[0]).toBe(`${BASE_URL}/api/v1/audit`);
    });
  });

  describe("getHealth", () => {
    it("sends GET /api/v1/health", async () => {
      mockFetchResponse({ state: "unlocked", version: "1.0.0" });
      const result = await client.getHealth();

      expect(result.state).toBe("unlocked");
      expect(result.version).toBe("1.0.0");
    });
  });

  describe("error handling", () => {
    it("maps error responses to VaultError with correct code", async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: async () => ({ error: ErrorCode.SECRET_NOT_FOUND, message: "Not found" }),
      });

      await expect(client.getSecretInfo("secret://missing")).rejects.toThrow(
        expect.objectContaining({ code: ErrorCode.SECRET_NOT_FOUND, message: "Not found" }),
      );
    });

    it("maps 401 responses to VaultError", async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ error: ErrorCode.TOKEN_EXPIRED, message: "Token expired" }),
      });

      await expect(client.listSecrets()).rejects.toThrow(
        expect.objectContaining({ code: ErrorCode.TOKEN_EXPIRED }),
      );
    });

    it("maps 503 responses to VaultError", async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: false,
        status: 503,
        json: async () => ({ error: ErrorCode.VAULT_LOCKED, message: "Vault is locked" }),
      });

      await expect(client.listSecrets()).rejects.toThrow(
        expect.objectContaining({ code: ErrorCode.VAULT_LOCKED }),
      );
    });

    it("falls back to INTERNAL_ERROR when error field is missing", async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: async () => ({ message: "Something broke" }),
      });

      await expect(client.listSecrets()).rejects.toThrow(
        expect.objectContaining({ code: ErrorCode.INTERNAL_ERROR }),
      );
    });

    it("sets Authorization header on all requests", async () => {
      mockFetchResponse([]);
      await client.listSecrets();

      const call = fetchSpy.mock.calls[0] as [string, RequestInit];
      const headers = call[1].headers as Record<string, string>;
      expect(headers.authorization).toBe(`Bearer ${TOKEN}`);
    });
  });
});
