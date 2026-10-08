import { describe, expect, it } from "vitest";

import {
  auditEventTypeSchema,
  createSecretInputSchema,
  followRedirectsSchema,
  handleSchema,
  httpActionSchema,
  httpMethodSchema,
  injectionTypeSchema,
  permissionSchema,
  principalTypeSchema,
  responseModeSchema,
  secretStatusSchema,
  secretTypeSchema,
  smtpActionSchema,
  vaultStateSchema,
} from "./schemas.js";

// ---------------------------------------------------------------------------
// Enum schemas
// ---------------------------------------------------------------------------

describe("enum schemas", () => {
  it("secretTypeSchema accepts valid values", () => {
    expect(secretTypeSchema.parse("api_key")).toBe("api_key");
    expect(secretTypeSchema.parse("oauth_token")).toBe("oauth_token");
    expect(secretTypeSchema.parse("certificate")).toBe("certificate");
  });

  it("secretTypeSchema rejects invalid values", () => {
    expect(() => secretTypeSchema.parse("password")).toThrow();
  });

  it("secretStatusSchema accepts valid values", () => {
    expect(secretStatusSchema.parse("active")).toBe("active");
    expect(secretStatusSchema.parse("pending")).toBe("pending");
    expect(secretStatusSchema.parse("expired")).toBe("expired");
    expect(secretStatusSchema.parse("revoked")).toBe("revoked");
  });

  it("injectionTypeSchema accepts valid values", () => {
    for (const v of ["header", "query", "basic_auth", "bearer"]) {
      expect(injectionTypeSchema.parse(v)).toBe(v);
    }
  });

  it("injectionTypeSchema rejects invalid values", () => {
    expect(() => injectionTypeSchema.parse("cookie")).toThrow();
  });

  it("httpMethodSchema accepts valid methods", () => {
    for (const m of ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]) {
      expect(httpMethodSchema.parse(m)).toBe(m);
    }
  });

  it("httpMethodSchema rejects invalid methods", () => {
    expect(() => httpMethodSchema.parse("CONNECT")).toThrow();
  });

  it("permissionSchema accepts all valid permissions", () => {
    for (const p of ["list", "read", "use", "create", "rotate", "revoke", "admin"]) {
      expect(permissionSchema.parse(p)).toBe(p);
    }
  });

  it("permissionSchema rejects invalid permission", () => {
    expect(() => permissionSchema.parse("delete")).toThrow();
  });

  it("auditEventTypeSchema accepts valid event types", () => {
    expect(auditEventTypeSchema.parse("vault.unlock")).toBe("vault.unlock");
    expect(auditEventTypeSchema.parse("secret.create")).toBe("secret.create");
    expect(auditEventTypeSchema.parse("access.denied")).toBe("access.denied");
    expect(auditEventTypeSchema.parse("mcp.spawn")).toBe("mcp.spawn");
    expect(auditEventTypeSchema.parse("mcp.crash")).toBe("mcp.crash");
    expect(auditEventTypeSchema.parse("mcp.terminate")).toBe("mcp.terminate");
  });

  it("principalTypeSchema accepts valid values", () => {
    for (const p of ["agent", "tool", "project", "user"]) {
      expect(principalTypeSchema.parse(p)).toBe(p);
    }
  });

  it("followRedirectsSchema accepts valid values", () => {
    expect(followRedirectsSchema.parse("same-origin")).toBe("same-origin");
    expect(followRedirectsSchema.parse("none")).toBe("none");
    expect(followRedirectsSchema.parse("any")).toBe("any");
  });

  it("responseModeSchema accepts valid values", () => {
    expect(responseModeSchema.parse("full")).toBe("full");
    expect(responseModeSchema.parse("filtered")).toBe("filtered");
    expect(responseModeSchema.parse("status_only")).toBe("status_only");
  });

  it("responseModeSchema rejects unknown values", () => {
    expect(() => responseModeSchema.parse("raw")).toThrow();
  });

  it("vaultStateSchema accepts valid values", () => {
    expect(vaultStateSchema.parse("sealed")).toBe("sealed");
    expect(vaultStateSchema.parse("unlocked")).toBe("unlocked");
  });

  it("vaultStateSchema rejects unknown values", () => {
    expect(() => vaultStateSchema.parse("open")).toThrow();
  });
});

// ---------------------------------------------------------------------------
// handleSchema
// ---------------------------------------------------------------------------

describe("handleSchema", () => {
  it("accepts valid handles", () => {
    expect(handleSchema.parse("secret://my-key")).toBe("secret://my-key");
    expect(handleSchema.parse("secret://proj/my-key")).toBe("secret://proj/my-key");
  });

  it("rejects invalid handles", () => {
    expect(() => handleSchema.parse("my-key")).toThrow();
    expect(() => handleSchema.parse("")).toThrow();
    expect(() => handleSchema.parse("secret://")).toThrow();
  });
});

// ---------------------------------------------------------------------------
// createSecretInputSchema
// ---------------------------------------------------------------------------

describe("createSecretInputSchema", () => {
  it("accepts valid minimal input", () => {
    const input = { name: "github-token", type: "api_key" };
    const result = createSecretInputSchema.parse(input);
    expect(result.name).toBe("github-token");
    expect(result.type).toBe("api_key");
    expect(result.project).toBeUndefined();
  });

  it("accepts input with all optional fields", () => {
    const input = {
      name: "github-token",
      type: "api_key",
      project: "my-api",
    };
    const result = createSecretInputSchema.parse(input);
    expect(result.project).toBe("my-api");
  });

  it("refuses the legacy create-time injection key instead of stripping it (R10/A5)", () => {
    // Accepted-and-discarded from v1.0 until 2026-09-02: a client still sending
    // it now learns so from the 400 rather than from a policy that never
    // existed.
    const result = createSecretInputSchema.safeParse({
      name: "github-token",
      type: "api_key",
      injection: { type: "bearer" },
    });
    expect(result.success).toBe(false);
    if (!result.success)
      expect(result.error.issues[0]?.message).toContain('Unrecognized key: "injection"');
  });

  it("rejects missing name", () => {
    expect(() => createSecretInputSchema.parse({ type: "api_key" })).toThrow();
  });

  it("rejects invalid type", () => {
    expect(() => createSecretInputSchema.parse({ name: "key", type: "password" })).toThrow();
  });

  it("rejects invalid name format", () => {
    expect(() => createSecretInputSchema.parse({ name: "has space", type: "api_key" })).toThrow();
  });

  it("rejects empty string project", () => {
    expect(() =>
      createSecretInputSchema.parse({ name: "key", type: "api_key", project: "" }),
    ).toThrow();
  });

  it("rejects project with dots", () => {
    expect(() =>
      createSecretInputSchema.parse({ name: "key", type: "api_key", project: "has.dot" }),
    ).toThrow();
  });

  it("accepts valid project name", () => {
    const result = createSecretInputSchema.parse({
      name: "key",
      type: "api_key",
      project: "valid-name",
    });
    expect(result.project).toBe("valid-name");
  });

  it("rejects name longer than 255 characters", () => {
    expect(() =>
      createSecretInputSchema.parse({ name: "a".repeat(256), type: "api_key" }),
    ).toThrow();
  });

  it("accepts name of exactly 255 characters", () => {
    const result = createSecretInputSchema.parse({ name: "a".repeat(255), type: "api_key" });
    expect(result.name).toBe("a".repeat(255));
  });

  it("accepts a base64 value and expires_at", () => {
    const value = Buffer.from("hunter2secret").toString("base64");
    const result = createSecretInputSchema.parse({
      name: "key",
      type: "api_key",
      value,
      expires_at: 1_700_000_000_000,
    });
    expect(result.value).toBe(value);
    expect(result.expires_at).toBe(1_700_000_000_000);
  });

  it("rejects a non-base64 value", () => {
    expect(() =>
      createSecretInputSchema.parse({ name: "key", type: "api_key", value: "not base64!!" }),
    ).toThrow();
  });

  it("rejects a non-integer expires_at", () => {
    expect(() =>
      createSecretInputSchema.parse({ name: "key", type: "api_key", expires_at: 1.5 }),
    ).toThrow();
  });

  it("rejects a non-positive expires_at", () => {
    expect(() =>
      createSecretInputSchema.parse({ name: "key", type: "api_key", expires_at: 0 }),
    ).toThrow();
  });
});

describe("string formats after the zod 4 sweep", () => {
  const SMTP_MIN = {
    type: "smtp",
    host: "smtp.example.com",
    from: "bot@example.com",
    to: ["ops@example.com"],
    subject: "hi",
    text: "body",
  };
  const HTTP_MIN = {
    type: "http",
    method: "GET",
    url: "https://api.github.com/user",
    injection: { type: "bearer" },
  };
  it("emailAddressSchema still refuses a bare local part and accepts an address", () => {
    expect(smtpActionSchema.safeParse({ ...SMTP_MIN, from: "nobody" }).success).toBe(false);
    expect(smtpActionSchema.safeParse({ ...SMTP_MIN, from: "a@b.example" }).success).toBe(true);
  });
  it("httpishUrlSchema still refuses ftp and accepts https", () => {
    expect(httpActionSchema.safeParse({ ...HTTP_MIN, url: "ftp://x.example/" }).success).toBe(
      false,
    );
    expect(httpActionSchema.safeParse({ ...HTTP_MIN, url: "https://x.example/" }).success).toBe(
      true,
    );
  });
  it("the base64 value field still refuses a non-base64 string", () => {
    expect(
      createSecretInputSchema.safeParse({ name: "k", type: "api_key", value: "***" }).success,
    ).toBe(false);
    expect(
      createSecretInputSchema.safeParse({ name: "k", type: "api_key", value: "YWJj" }).success,
    ).toBe(true);
  });
  it("httpishUrlSchema accepts a URL with surrounding whitespace and parses it trimmed (zod 4's z.url())", () => {
    const parsed = httpActionSchema.safeParse({ ...HTTP_MIN, url: " https://x.example/ " });
    expect(parsed.success).toBe(true);
    if (parsed.success) expect(parsed.data.url).toBe("https://x.example/");
  });
  it("an integer field refuses a value beyond the safe-integer range (zod 4's int())", () => {
    expect(
      createSecretInputSchema.safeParse({ name: "k", type: "api_key", expires_at: 2 ** 53 })
        .success,
    ).toBe(false);
    expect(
      createSecretInputSchema.safeParse({
        name: "k",
        type: "api_key",
        expires_at: 1_700_000_000_000,
      }).success,
    ).toBe(true);
  });
});
