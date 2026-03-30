import { describe, expect, it } from "vitest";

import {
  accessPolicyInputSchema,
  auditEventTypeSchema,
  auditQuerySchema,
  certificateImportSchema,
  createSecretInputSchema,
  followRedirectsSchema,
  handleSchema,
  httpMethodSchema,
  injectionConfigSchema,
  injectionTypeSchema,
  oauthGrantTypeSchema,
  oauthProviderConfigSchema,
  oauthProviderPresetSchema,
  permissionSchema,
  principalTypeSchema,
  secretStatusSchema,
  secretTypeSchema,
  sessionFileSchema,
  startOAuthFlowInputSchema,
  useSecretRequestSchema,
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
// injectionConfigSchema
// ---------------------------------------------------------------------------

describe("injectionConfigSchema", () => {
  it("accepts bearer (no extra fields)", () => {
    expect(injectionConfigSchema.parse({ type: "bearer" })).toEqual({ type: "bearer" });
  });

  it("accepts basic_auth", () => {
    expect(injectionConfigSchema.parse({ type: "basic_auth" })).toEqual({ type: "basic_auth" });
  });

  it("accepts header with header_name", () => {
    const result = injectionConfigSchema.parse({ type: "header", header_name: "X-API-Key" });
    expect(result).toEqual({ type: "header", header_name: "X-API-Key" });
  });

  it("rejects header without header_name", () => {
    expect(() => injectionConfigSchema.parse({ type: "header" })).toThrow();
  });

  it("accepts query with query_param", () => {
    const result = injectionConfigSchema.parse({ type: "query", query_param: "api_key" });
    expect(result).toEqual({ type: "query", query_param: "api_key" });
  });

  it("rejects query without query_param", () => {
    expect(() => injectionConfigSchema.parse({ type: "query" })).toThrow();
  });

  it("rejects unknown injection type", () => {
    expect(() => injectionConfigSchema.parse({ type: "cookie" })).toThrow();
  });

  it("rejects header with empty header_name", () => {
    expect(() => injectionConfigSchema.parse({ type: "header", header_name: "" })).toThrow();
  });

  it("rejects query with empty query_param", () => {
    expect(() => injectionConfigSchema.parse({ type: "query", query_param: "" })).toThrow();
  });

  it("accepts valid header_name characters", () => {
    expect(injectionConfigSchema.parse({ type: "header", header_name: "X-Api-Key" })).toEqual({
      type: "header",
      header_name: "X-Api-Key",
    });
    expect(injectionConfigSchema.parse({ type: "header", header_name: "x_custom" })).toEqual({
      type: "header",
      header_name: "x_custom",
    });
  });

  it("rejects header_name with spaces", () => {
    expect(() =>
      injectionConfigSchema.parse({ type: "header", header_name: "X-Api Key" }),
    ).toThrow();
  });

  it("rejects header_name with colons", () => {
    expect(() => injectionConfigSchema.parse({ type: "header", header_name: "X:Key" })).toThrow();
  });

  it("rejects header_name with CRLF", () => {
    expect(() =>
      injectionConfigSchema.parse({ type: "header", header_name: "Auth\r\n" }),
    ).toThrow();
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
    expect(result.injection).toBeUndefined();
  });

  it("accepts input with all optional fields", () => {
    const input = {
      name: "github-token",
      type: "api_key",
      project: "my-api",
      injection: { type: "bearer" as const },
    };
    const result = createSecretInputSchema.parse(input);
    expect(result.project).toBe("my-api");
    expect(result.injection).toEqual({ type: "bearer" });
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
});

// ---------------------------------------------------------------------------
// useSecretRequestSchema
// ---------------------------------------------------------------------------

describe("useSecretRequestSchema", () => {
  const validRequest = {
    handle: "secret://github-token",
    request: {
      method: "GET" as const,
      url: "https://api.github.com/user",
    },
    injection: { type: "bearer" as const },
  };

  it("accepts valid full request", () => {
    const result = useSecretRequestSchema.parse(validRequest);
    expect(result.handle).toBe("secret://github-token");
    expect(result.request.method).toBe("GET");
  });

  it("accepts request with all optional fields", () => {
    const result = useSecretRequestSchema.parse({
      ...validRequest,
      request: {
        ...validRequest.request,
        headers: { Accept: "application/json" },
        body: '{"key": "val"}',
        timeout_ms: 5000,
      },
      follow_redirects: "none",
    });
    expect(result.request.headers).toEqual({ Accept: "application/json" });
    expect(result.follow_redirects).toBe("none");
  });

  it("rejects invalid method", () => {
    expect(() =>
      useSecretRequestSchema.parse({
        ...validRequest,
        request: { ...validRequest.request, method: "CONNECT" },
      }),
    ).toThrow();
  });

  it("rejects invalid URL", () => {
    expect(() =>
      useSecretRequestSchema.parse({
        ...validRequest,
        request: { ...validRequest.request, url: "not-a-url" },
      }),
    ).toThrow();
  });

  it("rejects missing required fields", () => {
    expect(() => useSecretRequestSchema.parse({ handle: "secret://k" })).toThrow();
    expect(() => useSecretRequestSchema.parse({ ...validRequest, handle: undefined })).toThrow();
  });

  it("rejects timeout_ms: 0", () => {
    expect(() =>
      useSecretRequestSchema.parse({
        ...validRequest,
        request: { ...validRequest.request, timeout_ms: 0 },
      }),
    ).toThrow();
  });

  it("rejects timeout_ms: -1", () => {
    expect(() =>
      useSecretRequestSchema.parse({
        ...validRequest,
        request: { ...validRequest.request, timeout_ms: -1 },
      }),
    ).toThrow();
  });

  it("rejects timeout_ms: 1.5 (non-integer)", () => {
    expect(() =>
      useSecretRequestSchema.parse({
        ...validRequest,
        request: { ...validRequest.request, timeout_ms: 1.5 },
      }),
    ).toThrow();
  });

  it("accepts timeout_ms: 1", () => {
    const result = useSecretRequestSchema.parse({
      ...validRequest,
      request: { ...validRequest.request, timeout_ms: 1 },
    });
    expect(result.request.timeout_ms).toBe(1);
  });

  it("rejects timeout_ms exceeding 300000 (5 minutes)", () => {
    expect(() =>
      useSecretRequestSchema.parse({
        ...validRequest,
        request: { ...validRequest.request, timeout_ms: 300_001 },
      }),
    ).toThrow();
  });

  it("accepts timeout_ms: 300000 (5 minutes)", () => {
    const result = useSecretRequestSchema.parse({
      ...validRequest,
      request: { ...validRequest.request, timeout_ms: 300_000 },
    });
    expect(result.request.timeout_ms).toBe(300_000);
  });

  it.each(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] as const)(
    "accepts HTTP method %s",
    (method) => {
      const result = useSecretRequestSchema.parse({
        ...validRequest,
        request: { ...validRequest.request, method },
      });
      expect(result.request.method).toBe(method);
    },
  );
});

// ---------------------------------------------------------------------------
// accessPolicyInputSchema
// ---------------------------------------------------------------------------

describe("accessPolicyInputSchema", () => {
  it("accepts valid policy", () => {
    const result = accessPolicyInputSchema.parse({
      principal_type: "agent",
      principal_id: "claude-code",
      permissions: ["read", "use"],
    });
    expect(result.principal_type).toBe("agent");
    expect(result.permissions).toEqual(["read", "use"]);
  });

  it("rejects empty permissions array", () => {
    expect(() =>
      accessPolicyInputSchema.parse({
        principal_type: "agent",
        principal_id: "claude-code",
        permissions: [],
      }),
    ).toThrow();
  });

  it("rejects empty principal_id", () => {
    expect(() =>
      accessPolicyInputSchema.parse({
        principal_type: "agent",
        principal_id: "",
        permissions: ["read"],
      }),
    ).toThrow();
  });

  it("rejects expires_at: 0", () => {
    expect(() =>
      accessPolicyInputSchema.parse({
        principal_type: "agent",
        principal_id: "claude-code",
        permissions: ["read"],
        expires_at: 0,
      }),
    ).toThrow();
  });

  it("rejects expires_at: -1", () => {
    expect(() =>
      accessPolicyInputSchema.parse({
        principal_type: "agent",
        principal_id: "claude-code",
        permissions: ["read"],
        expires_at: -1,
      }),
    ).toThrow();
  });
});

// ---------------------------------------------------------------------------
// auditQuerySchema
// ---------------------------------------------------------------------------

describe("auditQuerySchema", () => {
  it("accepts empty query (all optional)", () => {
    expect(auditQuerySchema.parse({})).toEqual({});
  });

  it("accepts full query", () => {
    const result = auditQuerySchema.parse({
      event_type: "secret.create",
      limit: 100,
    });
    expect(result.event_type).toBe("secret.create");
    expect(result.limit).toBe(100);
  });

  it("rejects limit over 1000", () => {
    expect(() => auditQuerySchema.parse({ limit: 1001 })).toThrow();
  });

  it("rejects limit: 0", () => {
    expect(() => auditQuerySchema.parse({ limit: 0 })).toThrow();
  });

  it("accepts limit: 1 (minimum positive)", () => {
    expect(auditQuerySchema.parse({ limit: 1 }).limit).toBe(1);
  });

  it("accepts limit: 1000 (maximum)", () => {
    expect(auditQuerySchema.parse({ limit: 1000 }).limit).toBe(1000);
  });

  it("accepts since: 0 (nonnegative)", () => {
    expect(auditQuerySchema.parse({ since: 0 }).since).toBe(0);
  });

  it("rejects since: -1", () => {
    expect(() => auditQuerySchema.parse({ since: -1 })).toThrow();
  });

  it("accepts valid UUID for secret_id", () => {
    const uuid = "550e8400-e29b-41d4-a716-446655440000";
    expect(auditQuerySchema.parse({ secret_id: uuid }).secret_id).toBe(uuid);
  });

  it("rejects non-UUID secret_id", () => {
    expect(() => auditQuerySchema.parse({ secret_id: "not-uuid" })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// sessionFileSchema
// ---------------------------------------------------------------------------

describe("sessionFileSchema", () => {
  const validSession = {
    version: 1 as const,
    session_id: "01234567-89ab-cdef-0123-456789abcdef",
    vault_id: "vault-001",
    created_at: Date.now(),
    expires_at: Date.now() + 900_000,
    max_expires_at: Date.now() + 86_400_000,
    session_key: "c2Vzc2lvbi1rZXk=",
    wrapped_kek: "d3JhcHBlZC1rZWs=",
    wrapped_kek_iv: "aXY=",
    wrapped_kek_tag: "dGFn",
    wrapped_jwt_key: "and0LWtleQ==",
    wrapped_jwt_key_iv: "and0LWl2",
    wrapped_jwt_key_tag: "and0LXRhZw==",
    wrapped_audit_key: "YXVkaXQta2V5",
    wrapped_audit_key_iv: "YXVkaXQtaXY=",
    wrapped_audit_key_tag: "YXVkaXQtdGFn",
  };

  it("accepts valid session file", () => {
    const result = sessionFileSchema.parse(validSession);
    expect(result.version).toBe(1);
    expect(result.session_id).toBe(validSession.session_id);
  });

  it("rejects wrong version", () => {
    expect(() => sessionFileSchema.parse({ ...validSession, version: 2 })).toThrow();
  });

  it("rejects missing fields", () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { session_key: _omitted, ...incomplete } = validSession;
    expect(() => sessionFileSchema.parse(incomplete)).toThrow();
  });

  it("rejects empty string for base64 fields", () => {
    expect(() => sessionFileSchema.parse({ ...validSession, session_key: "" })).toThrow();
  });

  it.each([
    "session_key",
    "wrapped_kek",
    "wrapped_kek_iv",
    "wrapped_kek_tag",
    "wrapped_jwt_key",
    "wrapped_jwt_key_iv",
    "wrapped_jwt_key_tag",
    "wrapped_audit_key",
    "wrapped_audit_key_iv",
    "wrapped_audit_key_tag",
  ] as const)("rejects empty string for %s", (field) => {
    expect(() => sessionFileSchema.parse({ ...validSession, [field]: "" })).toThrow();
  });

  it("rejects created_at: 0", () => {
    expect(() => sessionFileSchema.parse({ ...validSession, created_at: 0 })).toThrow();
  });

  it("rejects created_at: -1", () => {
    expect(() => sessionFileSchema.parse({ ...validSession, created_at: -1 })).toThrow();
  });

  it("rejects non-base64 string for session_key", () => {
    expect(() =>
      sessionFileSchema.parse({ ...validSession, session_key: "not base64!!!" }),
    ).toThrow();
  });

  it("rejects non-base64 string for wrapped_kek", () => {
    expect(() =>
      sessionFileSchema.parse({ ...validSession, wrapped_kek: "%%%invalid%%%" }),
    ).toThrow();
  });
});

// ---------------------------------------------------------------------------
// oauthGrantTypeSchema
// ---------------------------------------------------------------------------

describe("oauthGrantTypeSchema", () => {
  it("accepts valid grant types", () => {
    expect(oauthGrantTypeSchema.parse("authorization_code")).toBe("authorization_code");
    expect(oauthGrantTypeSchema.parse("client_credentials")).toBe("client_credentials");
    expect(oauthGrantTypeSchema.parse("device_code")).toBe("device_code");
  });

  it("rejects invalid grant type", () => {
    expect(() => oauthGrantTypeSchema.parse("implicit")).toThrow();
  });
});

// ---------------------------------------------------------------------------
// oauthProviderPresetSchema
// ---------------------------------------------------------------------------

describe("oauthProviderPresetSchema", () => {
  it("accepts valid provider presets", () => {
    for (const p of ["github", "google", "microsoft", "slack", "custom"]) {
      expect(oauthProviderPresetSchema.parse(p)).toBe(p);
    }
  });

  it("rejects invalid provider preset", () => {
    expect(() => oauthProviderPresetSchema.parse("facebook")).toThrow();
  });
});

// ---------------------------------------------------------------------------
// oauthProviderConfigSchema
// ---------------------------------------------------------------------------

describe("oauthProviderConfigSchema", () => {
  const baseConfig = {
    provider: "github" as const,
    grant_type: "authorization_code" as const,
    token_endpoint: "https://github.com/login/oauth/access_token",
    auth_endpoint: "https://github.com/login/oauth/authorize",
    client_id: "client-123",
  };

  it("accepts valid authorization_code config", () => {
    const result = oauthProviderConfigSchema.parse(baseConfig);
    expect(result.provider).toBe("github");
    expect(result.grant_type).toBe("authorization_code");
  });

  it("accepts authorization_code with all optional fields", () => {
    const result = oauthProviderConfigSchema.parse({
      ...baseConfig,
      client_secret: "secret-456",
      scopes: ["repo", "user"],
      redirect_uri: "http://localhost:19876/oauth/callback",
      pkce_method: "S256",
    });
    expect(result.client_secret).toBe("secret-456");
    expect(result.scopes).toEqual(["repo", "user"]);
    expect(result.pkce_method).toBe("S256");
  });

  it("rejects authorization_code without auth_endpoint", () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { auth_endpoint: _omitted, ...noAuthEndpoint } = baseConfig;
    expect(() => oauthProviderConfigSchema.parse(noAuthEndpoint)).toThrow();
  });

  it("accepts valid client_credentials config", () => {
    const result = oauthProviderConfigSchema.parse({
      provider: "custom",
      grant_type: "client_credentials",
      token_endpoint: "https://auth.example.com/token",
      client_id: "client-123",
      client_secret: "secret-456",
    });
    expect(result.grant_type).toBe("client_credentials");
  });

  it("accepts valid device_code config", () => {
    const result = oauthProviderConfigSchema.parse({
      provider: "github",
      grant_type: "device_code",
      token_endpoint: "https://github.com/login/oauth/access_token",
      device_authorization_endpoint: "https://github.com/login/device/code",
      client_id: "client-123",
    });
    expect(result.grant_type).toBe("device_code");
  });

  it("rejects device_code without device_authorization_endpoint", () => {
    expect(() =>
      oauthProviderConfigSchema.parse({
        provider: "github",
        grant_type: "device_code",
        token_endpoint: "https://github.com/login/oauth/access_token",
        client_id: "client-123",
      }),
    ).toThrow();
  });

  it("rejects HTTP token_endpoint (requires HTTPS)", () => {
    expect(() =>
      oauthProviderConfigSchema.parse({
        ...baseConfig,
        token_endpoint: "http://github.com/login/oauth/access_token",
      }),
    ).toThrow();
  });

  it("rejects empty client_id", () => {
    expect(() =>
      oauthProviderConfigSchema.parse({
        ...baseConfig,
        client_id: "",
      }),
    ).toThrow();
  });

  it("rejects invalid pkce_method", () => {
    expect(() =>
      oauthProviderConfigSchema.parse({
        ...baseConfig,
        pkce_method: "plain",
      }),
    ).toThrow();
  });

  it("rejects empty scope strings", () => {
    expect(() =>
      oauthProviderConfigSchema.parse({
        ...baseConfig,
        scopes: [""],
      }),
    ).toThrow();
  });
});

// ---------------------------------------------------------------------------
// startOAuthFlowInputSchema
// ---------------------------------------------------------------------------

describe("startOAuthFlowInputSchema", () => {
  it("accepts valid minimal input", () => {
    const result = startOAuthFlowInputSchema.parse({
      name: "github-token",
      provider: "github",
      grant_type: "authorization_code",
      client_id: "client-123",
    });
    expect(result.name).toBe("github-token");
    expect(result.provider).toBe("github");
  });

  it("accepts input with all optional fields", () => {
    const result = startOAuthFlowInputSchema.parse({
      name: "github-token",
      provider: "github",
      grant_type: "authorization_code",
      client_id: "client-123",
      client_secret: "secret-456",
      scopes: ["repo"],
      project: "my-project",
      auth_endpoint: "https://github.com/login/oauth/authorize",
      token_endpoint: "https://github.com/login/oauth/access_token",
    });
    expect(result.project).toBe("my-project");
    expect(result.scopes).toEqual(["repo"]);
  });

  it("rejects invalid name format", () => {
    expect(() =>
      startOAuthFlowInputSchema.parse({
        name: "has space",
        provider: "github",
        grant_type: "authorization_code",
        client_id: "client-123",
      }),
    ).toThrow();
  });

  it("rejects empty client_id", () => {
    expect(() =>
      startOAuthFlowInputSchema.parse({
        name: "token",
        provider: "github",
        grant_type: "authorization_code",
        client_id: "",
      }),
    ).toThrow();
  });

  it("rejects HTTP endpoints (requires HTTPS)", () => {
    expect(() =>
      startOAuthFlowInputSchema.parse({
        name: "token",
        provider: "github",
        grant_type: "authorization_code",
        client_id: "client-123",
        token_endpoint: "http://insecure.example.com/token",
      }),
    ).toThrow();
  });
});

// ---------------------------------------------------------------------------
// certificateImportSchema
// ---------------------------------------------------------------------------

describe("certificateImportSchema", () => {
  const validPem = "-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----";
  const validCertPem = "-----BEGIN CERTIFICATE-----\nMIIEvQ...\n-----END CERTIFICATE-----";

  it("accepts valid minimal input", () => {
    const result = certificateImportSchema.parse({
      name: "my-cert",
      private_key_pem: validPem,
    });
    expect(result.name).toBe("my-cert");
    expect(result.auto_renew).toBe(false);
    expect(result.renew_before_days).toBe(30);
  });

  it("accepts input with all optional fields", () => {
    const result = certificateImportSchema.parse({
      name: "my-cert",
      private_key_pem: validPem,
      certificate_pem: validCertPem,
      chain_pem: validCertPem,
      project: "my-project",
      auto_renew: true,
      renew_before_days: 60,
    });
    expect(result.auto_renew).toBe(true);
    expect(result.renew_before_days).toBe(60);
    expect(result.project).toBe("my-project");
  });

  it("rejects non-PEM private key", () => {
    expect(() =>
      certificateImportSchema.parse({
        name: "my-cert",
        private_key_pem: "not-a-pem-value",
      }),
    ).toThrow();
  });

  it("rejects empty private_key_pem", () => {
    expect(() =>
      certificateImportSchema.parse({
        name: "my-cert",
        private_key_pem: "",
      }),
    ).toThrow();
  });

  it("rejects invalid name format", () => {
    expect(() =>
      certificateImportSchema.parse({
        name: "has space",
        private_key_pem: validPem,
      }),
    ).toThrow();
  });

  it("rejects renew_before_days over 365", () => {
    expect(() =>
      certificateImportSchema.parse({
        name: "my-cert",
        private_key_pem: validPem,
        renew_before_days: 366,
      }),
    ).toThrow();
  });

  it("rejects renew_before_days: 0", () => {
    expect(() =>
      certificateImportSchema.parse({
        name: "my-cert",
        private_key_pem: validPem,
        renew_before_days: 0,
      }),
    ).toThrow();
  });

  it("accepts renew_before_days: 1 (minimum)", () => {
    const result = certificateImportSchema.parse({
      name: "my-cert",
      private_key_pem: validPem,
      renew_before_days: 1,
    });
    expect(result.renew_before_days).toBe(1);
  });

  it("accepts renew_before_days: 365 (maximum)", () => {
    const result = certificateImportSchema.parse({
      name: "my-cert",
      private_key_pem: validPem,
      renew_before_days: 365,
    });
    expect(result.renew_before_days).toBe(365);
  });

  it("rejects non-PEM certificate_pem", () => {
    expect(() =>
      certificateImportSchema.parse({
        name: "my-cert",
        private_key_pem: validPem,
        certificate_pem: "not-pem",
      }),
    ).toThrow();
  });
});
