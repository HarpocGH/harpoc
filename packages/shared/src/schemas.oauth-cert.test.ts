import { describe, expect, it } from "vitest";

import {
  certificateImportSchema,
  generateCsrRequestSchema,
  oauthGrantTypeSchema,
  oauthProviderConfigSchema,
  oauthProviderPresetSchema,
  startOAuthFlowInputSchema,
} from "./schemas.js";

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

  it("accepts loopback HTTP endpoints (dev/test providers)", () => {
    const result = oauthProviderConfigSchema.parse({
      ...baseConfig,
      token_endpoint: "http://127.0.0.1:8080/token",
      auth_endpoint: "http://localhost:8080/authorize",
    });
    expect(result.token_endpoint).toBe("http://127.0.0.1:8080/token");
  });

  it("accepts IPv6 loopback HTTP token_endpoint", () => {
    const result = oauthProviderConfigSchema.parse({
      ...baseConfig,
      token_endpoint: "http://[::1]:8080/token",
    });
    expect(result.token_endpoint).toBe("http://[::1]:8080/token");
  });

  it("rejects non-loopback HTTP token_endpoint (private-range IP)", () => {
    expect(() =>
      oauthProviderConfigSchema.parse({
        ...baseConfig,
        token_endpoint: "http://192.168.1.10:8080/token",
      }),
    ).toThrow();
  });

  it("rejects non-loopback HTTP auth_endpoint", () => {
    expect(() =>
      oauthProviderConfigSchema.parse({
        ...baseConfig,
        auth_endpoint: "http://example.com/authorize",
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

  it("accepts loopback HTTP endpoints", () => {
    const result = startOAuthFlowInputSchema.parse({
      name: "token",
      provider: "custom",
      grant_type: "client_credentials",
      client_id: "client-123",
      token_endpoint: "http://127.0.0.1:9999/token",
    });
    expect(result.token_endpoint).toBe("http://127.0.0.1:9999/token");
  });

  it("rejects non-loopback HTTP device_authorization_endpoint", () => {
    expect(() =>
      startOAuthFlowInputSchema.parse({
        name: "token",
        provider: "custom",
        grant_type: "device_code",
        client_id: "client-123",
        device_authorization_endpoint: "http://10.0.0.5/device",
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

  it("rejects a missing certificate_pem", () => {
    expect(() =>
      certificateImportSchema.parse({
        name: "my-cert",
        private_key_pem: validPem,
      }),
    ).toThrow();
  });

  it("accepts valid minimal input with certificate_pem", () => {
    const result = certificateImportSchema.parse({
      name: "my-cert",
      private_key_pem: validPem,
      certificate_pem: validCertPem,
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
        certificate_pem: validCertPem,
      }),
    ).toThrow();
  });

  it("rejects empty private_key_pem", () => {
    expect(() =>
      certificateImportSchema.parse({
        name: "my-cert",
        private_key_pem: "",
        certificate_pem: validCertPem,
      }),
    ).toThrow();
  });

  it("rejects invalid name format", () => {
    expect(() =>
      certificateImportSchema.parse({
        name: "has space",
        private_key_pem: validPem,
        certificate_pem: validCertPem,
      }),
    ).toThrow();
  });

  it("rejects renew_before_days over 365", () => {
    expect(() =>
      certificateImportSchema.parse({
        name: "my-cert",
        private_key_pem: validPem,
        certificate_pem: validCertPem,
        renew_before_days: 366,
      }),
    ).toThrow();
  });

  it("rejects renew_before_days: 0", () => {
    expect(() =>
      certificateImportSchema.parse({
        name: "my-cert",
        private_key_pem: validPem,
        certificate_pem: validCertPem,
        renew_before_days: 0,
      }),
    ).toThrow();
  });

  it("accepts renew_before_days: 1 (minimum)", () => {
    const result = certificateImportSchema.parse({
      name: "my-cert",
      private_key_pem: validPem,
      certificate_pem: validCertPem,
      renew_before_days: 1,
    });
    expect(result.renew_before_days).toBe(1);
  });

  it("accepts renew_before_days: 365 (maximum)", () => {
    const result = certificateImportSchema.parse({
      name: "my-cert",
      private_key_pem: validPem,
      certificate_pem: validCertPem,
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

// ---------------------------------------------------------------------------
// generateCsrRequestSchema
// ---------------------------------------------------------------------------

describe("generateCsrRequestSchema", () => {
  it("accepts a minimal EC request (default algorithm)", () => {
    const r = generateCsrRequestSchema.safeParse({ name: "web-cert", subject: "example.com" });
    expect(r.success).toBe(true);
  });
  it("accepts bits with algorithm rsa", () => {
    expect(
      generateCsrRequestSchema.safeParse({
        name: "web-cert",
        subject: "example.com",
        algorithm: "rsa",
        bits: 4096,
      }).success,
    ).toBe(true);
  });
  it("refuses bits without algorithm rsa (the CLI's pairing rule)", () => {
    expect(
      generateCsrRequestSchema.safeParse({ name: "web-cert", subject: "example.com", bits: 2048 })
        .success,
    ).toBe(false);
  });
  it("refuses curve with algorithm rsa", () => {
    expect(
      generateCsrRequestSchema.safeParse({
        name: "web-cert",
        subject: "example.com",
        algorithm: "rsa",
        curve: "P-256",
      }).success,
    ).toBe(false);
  });
  it("accepts curve with algorithm ec", () => {
    expect(
      generateCsrRequestSchema.safeParse({
        name: "web-cert",
        subject: "example.com",
        algorithm: "ec",
        curve: "P-384",
      }).success,
    ).toBe(true);
  });
  it("refuses bits outside 2048/4096 (1024)", () => {
    const r = generateCsrRequestSchema.safeParse({
      name: "web-cert",
      subject: "example.com",
      algorithm: "rsa",
      bits: 1024,
    });
    expect(r.success).toBe(false);
    if (!r.success) expect(r.error.issues.map((i) => i.path)).toEqual([["bits"]]);
  });
  it("refuses a curve outside P-256/P-384 (P-521)", () => {
    const r = generateCsrRequestSchema.safeParse({
      name: "web-cert",
      subject: "example.com",
      algorithm: "ec",
      curve: "P-521",
    });
    expect(r.success).toBe(false);
    if (!r.success) expect(r.error.issues.map((i) => i.path)).toEqual([["curve"]]);
  });
});
