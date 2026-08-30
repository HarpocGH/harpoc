import { describe, expect, it } from "vitest";

import {
  accessPolicyInputSchema,
  agentNameSchema,
  auditChainAnchorSchema,
  auditEventTypeSchema,
  auditQuerySchema,
  certificateImportSchema,
  connectionConfigSchema,
  createSecretInputSchema,
  databaseActionSchema,
  dockerRegistryActionSchema,
  followRedirectsSchema,
  generateCsrRequestSchema,
  handleSchema,
  healthResponseSchema,
  httpActionSchema,
  httpMethodSchema,
  imapActionSchema,
  injectionConfigSchema,
  injectionPolicyInputSchema,
  injectionTypeSchema,
  listAgentsQuerySchema,
  listTokensQuerySchema,
  mcpActionSchema,
  mcpServerConfigSchema,
  mcpTransportSchema,
  oauthGrantTypeSchema,
  oauthProviderConfigSchema,
  oauthProviderPresetSchema,
  permissionSchema,
  principalTypeSchema,
  processActionSchema,
  registerAgentInputSchema,
  renewCertificateRequestSchema,
  responseModeSchema,
  secretStatusSchema,
  secretTypeSchema,
  sessionFileSchema,
  setAgentPermissionsInputSchema,
  setInjectionPolicyRequestSchema,
  sftpActionSchema,
  smtpActionSchema,
  sshActionSchema,
  startOAuthFlowInputSchema,
  updateAgentInputSchema,
  useSecretActionSchema,
  useSecretRequestSchema,
  vaultStateSchema,
  websocketActionSchema,
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

  it("strips a legacy create-time injection config instead of storing or rejecting it", () => {
    // The field was accepted-and-discarded before its removal; old clients
    // sending it must not start failing, but nothing may pretend to store it.
    const result = createSecretInputSchema.parse({
      name: "github-token",
      type: "api_key",
      injection: { type: "bearer" },
    });
    expect(result).not.toHaveProperty("injection");
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

// ---------------------------------------------------------------------------
// httpActionSchema
// ---------------------------------------------------------------------------

describe("httpActionSchema", () => {
  const validHttp = {
    type: "http" as const,
    method: "GET" as const,
    url: "https://api.github.com/user",
    injection: { type: "bearer" as const },
  };

  it("accepts a minimal HTTP action", () => {
    const result = httpActionSchema.parse(validHttp);
    expect(result.type).toBe("http");
    expect(result.method).toBe("GET");
  });

  it("accepts all optional fields", () => {
    const result = httpActionSchema.parse({
      ...validHttp,
      headers: { Accept: "application/json" },
      body: '{"key":"val"}',
      follow_redirects: "none",
      timeout_ms: 5_000,
      response_mode: "status_only",
    });
    expect(result.headers).toEqual({ Accept: "application/json" });
    expect(result.follow_redirects).toBe("none");
    expect(result.timeout_ms).toBe(5_000);
    expect(result.response_mode).toBe("status_only");
  });

  it("leaves response_mode undefined when omitted", () => {
    expect(httpActionSchema.parse(validHttp).response_mode).toBeUndefined();
  });

  it("rejects an invalid response_mode", () => {
    expect(() => httpActionSchema.parse({ ...validHttp, response_mode: "raw" })).toThrow();
  });

  it("rejects invalid method", () => {
    expect(() => httpActionSchema.parse({ ...validHttp, method: "CONNECT" })).toThrow();
  });

  it("rejects invalid URL", () => {
    expect(() => httpActionSchema.parse({ ...validHttp, url: "not-a-url" })).toThrow();
  });

  it("rejects timeout_ms: 0", () => {
    expect(() => httpActionSchema.parse({ ...validHttp, timeout_ms: 0 })).toThrow();
  });

  it("rejects timeout_ms exceeding 300000", () => {
    expect(() => httpActionSchema.parse({ ...validHttp, timeout_ms: 300_001 })).toThrow();
  });

  it("accepts timeout_ms: 300000", () => {
    expect(httpActionSchema.parse({ ...validHttp, timeout_ms: 300_000 }).timeout_ms).toBe(300_000);
  });

  it.each(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] as const)(
    "accepts HTTP method %s",
    (method) => {
      expect(httpActionSchema.parse({ ...validHttp, method }).method).toBe(method);
    },
  );
});

// ---------------------------------------------------------------------------
// processActionSchema
// ---------------------------------------------------------------------------

describe("processActionSchema", () => {
  const validProcess = {
    type: "process" as const,
    command: "gh",
    env_var: "GH_TOKEN",
  };

  it("accepts a minimal process action", () => {
    const result = processActionSchema.parse(validProcess);
    expect(result.type).toBe("process");
    expect(result.command).toBe("gh");
    expect(result.env_var).toBe("GH_TOKEN");
  });

  it("accepts all optional fields", () => {
    const result = processActionSchema.parse({
      ...validProcess,
      args: ["api", "/user/repos"],
      working_directory: "/home/user/project",
      timeout_ms: 10_000,
    });
    expect(result.args).toEqual(["api", "/user/repos"]);
    expect(result.working_directory).toBe("/home/user/project");
  });

  it("rejects empty command", () => {
    expect(() => processActionSchema.parse({ ...validProcess, command: "" })).toThrow();
  });

  it("rejects missing env_var", () => {
    expect(() => processActionSchema.parse({ type: "process", command: "gh" })).toThrow();
  });

  it.each(["1BAD", "has-dash", "has space", "with.dot", ""])(
    "rejects invalid env_var name %j",
    (env_var) => {
      expect(() => processActionSchema.parse({ ...validProcess, env_var })).toThrow();
    },
  );

  it.each(["GH_TOKEN", "_underscore", "A", "PATH2"])("accepts valid env_var name %j", (env_var) => {
    expect(processActionSchema.parse({ ...validProcess, env_var }).env_var).toBe(env_var);
  });

  it("rejects args beyond the max count", () => {
    const args = Array.from({ length: 257 }, () => "x");
    expect(() => processActionSchema.parse({ ...validProcess, args })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// mcpActionSchema
// ---------------------------------------------------------------------------

describe("mcpActionSchema", () => {
  const validMcp = {
    type: "mcp",
    server: "github-mcp",
    tool: "list_repositories",
  };

  it("accepts a minimal mcp action", () => {
    const result = mcpActionSchema.parse(validMcp);
    expect(result.server).toBe("github-mcp");
    expect(result.tool).toBe("list_repositories");
  });

  it("accepts arguments and timeout_ms", () => {
    const result = mcpActionSchema.parse({
      ...validMcp,
      arguments: { visibility: "public", count: 10 },
      timeout_ms: 5_000,
    });
    expect(result.arguments).toEqual({ visibility: "public", count: 10 });
    expect(result.timeout_ms).toBe(5_000);
  });

  it("rejects an invalid server name format", () => {
    expect(() => mcpActionSchema.parse({ ...validMcp, server: "bad name!" })).toThrow();
  });

  it("rejects a missing tool", () => {
    expect(() => mcpActionSchema.parse({ type: "mcp", server: "github-mcp" })).toThrow();
  });

  it("rejects a timeout above the cap", () => {
    expect(() => mcpActionSchema.parse({ ...validMcp, timeout_ms: 300_001 })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// useSecretActionSchema (discriminated union)
// ---------------------------------------------------------------------------

describe("useSecretActionSchema", () => {
  it("accepts an http action", () => {
    const result = useSecretActionSchema.parse({
      type: "http",
      method: "GET",
      url: "https://api.github.com/user",
      injection: { type: "bearer" },
    });
    expect(result.type).toBe("http");
  });

  it("accepts a process action", () => {
    const result = useSecretActionSchema.parse({
      type: "process",
      command: "gh",
      env_var: "GH_TOKEN",
    });
    expect(result.type).toBe("process");
  });

  it("accepts an mcp action", () => {
    const result = useSecretActionSchema.parse({
      type: "mcp",
      server: "github-mcp",
      tool: "list_repositories",
      arguments: { visibility: "public" },
    });
    expect(result.type).toBe("mcp");
  });

  it("accepts a database action", () => {
    const result = useSecretActionSchema.parse({
      type: "database",
      engine: "postgresql",
      host: "db.example.com:5432",
      database: "app_production",
      query: "SELECT 1",
    });
    expect(result.type).toBe("database");
  });

  it("accepts a git action", () => {
    const result = useSecretActionSchema.parse({
      type: "git",
      operation: "clone",
      repository: "https://github.com/user/repo.git",
      args: ["--depth", "1"],
    });
    expect(result.type).toBe("git");
  });

  it("accepts an ssh action", () => {
    const result = useSecretActionSchema.parse({
      type: "ssh",
      host: "deploy.example.com",
      user: "deploy",
      command: "systemctl restart app",
    });
    expect(result.type).toBe("ssh");
  });

  it("rejects an unknown action type", () => {
    expect(() => useSecretActionSchema.parse({ type: "telnet", command: "ls" })).toThrow();
  });

  it("rejects a database action with an unsupported engine", () => {
    expect(() =>
      useSecretActionSchema.parse({
        type: "database",
        engine: "oracle",
        host: "db.example.com",
        database: "app",
        query: "SELECT 1",
      }),
    ).toThrow();
  });

  it("rejects a missing discriminant", () => {
    expect(() => useSecretActionSchema.parse({ command: "gh", env_var: "GH_TOKEN" })).toThrow();
  });

  it("surfaces a field-level error at the top level of error.issues, not buried in unionErrors", () => {
    // REST (routes/secrets.ts) and CLI (commands/secret/use.ts) both read
    // error.issues directly, never error.unionErrors — a plain z.union
    // buries per-branch field errors there, degrading every field-level
    // refusal (missing/invalid required field) on every action type to a
    // bare "Invalid input". discriminatedUnion keeps them at the top level.
    const result = useSecretActionSchema.safeParse({
      type: "http",
      method: "GET",
      injection: { type: "bearer" },
      // url omitted
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.length).toBeGreaterThan(0);
      const urlIssue = result.error.issues.find((issue) => issue.path.includes("url"));
      expect(urlIssue).toBeDefined();
    }
  });
});

// ---------------------------------------------------------------------------
// useSecretRequestSchema
// ---------------------------------------------------------------------------

describe("useSecretRequestSchema", () => {
  it("accepts an http request", () => {
    const result = useSecretRequestSchema.parse({
      handle: "secret://github-token",
      action: {
        type: "http",
        method: "GET",
        url: "https://api.github.com/user",
        injection: { type: "bearer" },
      },
    });
    expect(result.handle).toBe("secret://github-token");
    expect(result.action.type).toBe("http");
  });

  it("accepts a process request", () => {
    const result = useSecretRequestSchema.parse({
      handle: "secret://gh-token",
      action: { type: "process", command: "gh", args: ["api"], env_var: "GH_TOKEN" },
    });
    expect(result.action.type).toBe("process");
  });

  it("rejects a missing handle", () => {
    expect(() =>
      useSecretRequestSchema.parse({
        action: { type: "process", command: "gh", env_var: "GH_TOKEN" },
      }),
    ).toThrow();
  });

  it("rejects a missing action", () => {
    expect(() => useSecretRequestSchema.parse({ handle: "secret://k" })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// injectionPolicyInputSchema
// ---------------------------------------------------------------------------

describe("injectionPolicyInputSchema", () => {
  it("defaults all allowlists to empty arrays and response_mode to filtered", () => {
    const result = injectionPolicyInputSchema.parse({});
    expect(result).toEqual({
      url_allowlist: [],
      command_allowlist: [],
      env_allowlist: [],
      host_allowlist: [],
      response_mode: "filtered",
      response_header_allowlist: [],
      network_isolation: false,
      fs_isolation: false,
      smtp_recipient_allowlist: [],
      imap_read_only: false,
    });
  });

  it("defaults network_isolation to false and round-trips true", () => {
    expect(injectionPolicyInputSchema.parse({}).network_isolation).toBe(false);
    const enabled = injectionPolicyInputSchema.parse({ network_isolation: true });
    expect(enabled.network_isolation).toBe(true);
    expect(
      injectionPolicyInputSchema.parse(JSON.parse(JSON.stringify(enabled))).network_isolation,
    ).toBe(true);
  });

  it("accepts a legacy body without network_isolation (REST back-compat)", () => {
    const result = injectionPolicyInputSchema.parse({
      url_allowlist: ["https://api.github.com/*"],
      response_mode: "status_only",
    });
    expect(result.network_isolation).toBe(false);
    expect(result.response_mode).toBe("status_only");
  });

  it("rejects a non-boolean network_isolation", () => {
    expect(() => injectionPolicyInputSchema.parse({ network_isolation: "yes" })).toThrow();
    expect(() => injectionPolicyInputSchema.parse({ network_isolation: 1 })).toThrow();
  });

  it("fs_isolation defaults to false when absent", () => {
    const parsed = injectionPolicyInputSchema.parse({});
    expect(parsed.fs_isolation).toBe(false);
  });

  it("fs_isolation accepts explicit true", () => {
    expect(injectionPolicyInputSchema.parse({ fs_isolation: true }).fs_isolation).toBe(true);
  });

  it("accepts populated allowlists", () => {
    const result = injectionPolicyInputSchema.parse({
      url_allowlist: ["https://api.github.com/*"],
      command_allowlist: ["gh", "/usr/bin/git"],
      env_allowlist: ["PATH", "HOME"],
    });
    expect(result.command_allowlist).toEqual(["gh", "/usr/bin/git"]);
  });

  it("rejects an invalid env var name in env_allowlist", () => {
    expect(() => injectionPolicyInputSchema.parse({ env_allowlist: ["has-dash"] })).toThrow();
  });

  it("rejects an empty command allowlist entry", () => {
    expect(() => injectionPolicyInputSchema.parse({ command_allowlist: [""] })).toThrow();
  });

  it("accepts response_mode and response_header_allowlist", () => {
    const result = injectionPolicyInputSchema.parse({
      response_mode: "status_only",
      response_header_allowlist: ["Content-Type", "X-Request-Id"],
    });
    expect(result.response_mode).toBe("status_only");
    expect(result.response_header_allowlist).toEqual(["Content-Type", "X-Request-Id"]);
  });

  it("rejects an invalid response_mode", () => {
    expect(() => injectionPolicyInputSchema.parse({ response_mode: "raw" })).toThrow();
  });

  it("rejects invalid response header names", () => {
    expect(() =>
      injectionPolicyInputSchema.parse({ response_header_allowlist: ["Bad: Header"] }),
    ).toThrow();
    expect(() =>
      injectionPolicyInputSchema.parse({ response_header_allowlist: ["x\r\ny"] }),
    ).toThrow();
    expect(() => injectionPolicyInputSchema.parse({ response_header_allowlist: [""] })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// setInjectionPolicyRequestSchema
// ---------------------------------------------------------------------------

describe("setInjectionPolicyRequestSchema", () => {
  it("defaults acknowledge_interpreters to false", () => {
    const result = setInjectionPolicyRequestSchema.parse({ command_allowlist: ["gh"] });
    expect(result.acknowledge_interpreters).toBe(false);
    expect(result.command_allowlist).toEqual(["gh"]);
  });

  it("accepts an explicit acknowledgement", () => {
    const result = setInjectionPolicyRequestSchema.parse({
      command_allowlist: ["python"],
      acknowledge_interpreters: true,
    });
    expect(result.acknowledge_interpreters).toBe(true);
  });

  it("rejects a non-boolean acknowledgement", () => {
    expect(() =>
      setInjectionPolicyRequestSchema.parse({ acknowledge_interpreters: "yes" }),
    ).toThrow();
  });

  it("legacy bodies without fs_isolation still parse", () => {
    const parsed = setInjectionPolicyRequestSchema.parse({ url_allowlist: [] });
    expect(parsed.fs_isolation).toBe(false);
  });

  it("still validates the policy fields", () => {
    expect(() =>
      setInjectionPolicyRequestSchema.parse({
        command_allowlist: [""],
        acknowledge_interpreters: true,
      }),
    ).toThrow();
  });
});

// ---------------------------------------------------------------------------
// mcpServerConfigSchema
// ---------------------------------------------------------------------------

describe("mcpTransportSchema", () => {
  it("accepts stdio and http", () => {
    expect(mcpTransportSchema.parse("stdio")).toBe("stdio");
    expect(mcpTransportSchema.parse("http")).toBe("http");
  });

  it("rejects unknown transports", () => {
    expect(() => mcpTransportSchema.parse("sse")).toThrow();
  });
});

describe("mcpServerConfigSchema", () => {
  const validStdio = {
    server_name: "github-mcp",
    transport: "stdio",
    command: "node",
    args: ["server.js"],
    env_var: "GITHUB_TOKEN",
  };

  const validHttp = {
    server_name: "remote-mcp",
    transport: "http",
    url: "https://mcp.example.com/mcp",
  };

  it("accepts a valid stdio config", () => {
    const result = mcpServerConfigSchema.parse(validStdio);
    expect(result.transport).toBe("stdio");
    expect(result.command).toBe("node");
  });

  it("accepts a valid http config", () => {
    const result = mcpServerConfigSchema.parse(validHttp);
    expect(result.transport).toBe("http");
    expect(result.url).toBe("https://mcp.example.com/mcp");
  });

  it("rejects stdio without a command", () => {
    expect(() =>
      mcpServerConfigSchema.parse({
        server_name: "x",
        transport: "stdio",
        env_var: "TOKEN",
      }),
    ).toThrow();
  });

  it("rejects stdio without an env_var", () => {
    expect(() =>
      mcpServerConfigSchema.parse({
        server_name: "x",
        transport: "stdio",
        command: "node",
      }),
    ).toThrow();
  });

  it("rejects http without a url", () => {
    expect(() => mcpServerConfigSchema.parse({ server_name: "x", transport: "http" })).toThrow();
  });

  it("rejects an invalid env_var name", () => {
    expect(() => mcpServerConfigSchema.parse({ ...validStdio, env_var: "has-dash" })).toThrow();
  });

  it("rejects an invalid server_name format", () => {
    expect(() => mcpServerConfigSchema.parse({ ...validStdio, server_name: "bad name" })).toThrow();
  });
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

  it("refuses an agent-type principal_id that is not a valid agent name (C34)", () => {
    const base = { permissions: ["read"] as const, principal_type: "agent" as const };
    expect(accessPolicyInputSchema.safeParse({ ...base, principal_id: "a b" }).success).toBe(false);
    expect(accessPolicyInputSchema.safeParse({ ...base, principal_id: "svc-1" }).success).toBe(
      true,
    );
    // tool/user principals stay free-string.
    expect(
      accessPolicyInputSchema.safeParse({ ...base, principal_type: "tool", principal_id: "a b" })
        .success,
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// healthResponseSchema
// ---------------------------------------------------------------------------

describe("healthResponseSchema", () => {
  it("accepts a valid health response", () => {
    const result = healthResponseSchema.parse({ state: "unlocked", version: "1.0.0" });
    expect(result.state).toBe("unlocked");
    expect(result.version).toBe("1.0.0");
  });

  it("rejects an unknown state", () => {
    expect(() => healthResponseSchema.parse({ state: "open", version: "1.0.0" })).toThrow();
  });

  it("rejects a missing version", () => {
    expect(() => healthResponseSchema.parse({ state: "sealed" })).toThrow();
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

  it("accepts success: true and success: false", () => {
    expect(auditQuerySchema.parse({ success: true }).success).toBe(true);
    expect(auditQuerySchema.parse({ success: false }).success).toBe(false);
  });

  it("rejects non-boolean success", () => {
    expect(() => auditQuerySchema.parse({ success: "false" })).toThrow();
  });

  it("accepts principal_type: 'agent' with principal_id (v1.4)", () => {
    const result = auditQuerySchema.parse({ principal_type: "agent", principal_id: "claude-code" });
    expect(result.principal_type).toBe("agent");
    expect(result.principal_id).toBe("claude-code");
  });

  it("rejects an unknown principal_type (v1.4)", () => {
    expect(() => auditQuerySchema.parse({ principal_type: "robot" })).toThrow();
  });

  it("rejects an empty principal_id (v1.4)", () => {
    expect(() => auditQuerySchema.parse({ principal_id: "" })).toThrow();
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
    key_protection: "none" as const,
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

  it("accepts every key_protection scheme", () => {
    for (const scheme of ["none", "dpapi", "keychain", "secret-service", "keyring"] as const) {
      expect(
        sessionFileSchema.parse({ ...validSession, key_protection: scheme }).key_protection,
      ).toBe(scheme);
    }
  });

  it("requires key_protection (a field-less file is refused, forcing a re-unlock)", () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { key_protection: _omitted, ...withoutField } = validSession;
    expect(sessionFileSchema.safeParse(withoutField).success).toBe(false);
  });

  it("rejects unknown key_protection values", () => {
    expect(() => sessionFileSchema.parse({ ...validSession, key_protection: "tpm" })).toThrow();
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
// generateCsrRequestSchema / renewCertificateRequestSchema
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
});

describe("renewCertificateRequestSchema", () => {
  it("accepts an empty body and a valid port; refuses port 0 and 65536", () => {
    expect(renewCertificateRequestSchema.safeParse({}).success).toBe(true);
    expect(renewCertificateRequestSchema.safeParse({ http_port: 8080 }).success).toBe(true);
    expect(renewCertificateRequestSchema.safeParse({ http_port: 0 }).success).toBe(false);
    expect(renewCertificateRequestSchema.safeParse({ http_port: 65536 }).success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Input-validation hardening (code review 2026-07-07, Low group 3)
// ---------------------------------------------------------------------------

describe("sshActionSchema argv hardening", () => {
  const validSsh = {
    type: "ssh" as const,
    host: "deploy.example.com",
    user: "deploy",
    command: "whoami",
  };

  it("accepts a normal host and user", () => {
    expect(sshActionSchema.parse(validSsh).host).toBe("deploy.example.com");
  });

  it.each(["-evil", "-oProxyCommand.x", ".evil", "-l"])(
    "rejects host %s (leading dash/dot)",
    (host) => {
      expect(() => sshActionSchema.parse({ ...validSsh, host })).toThrow();
    },
  );

  it.each(["-root", ".hidden"])("rejects user %s (leading dash/dot)", (user) => {
    expect(() => sshActionSchema.parse({ ...validSsh, user })).toThrow();
  });

  it("accepts an optional port in range and refuses 0, 65536 and a string", () => {
    expect(sshActionSchema.parse({ ...validSsh, port: 2222 }).port).toBe(2222);
    expect(sshActionSchema.parse(validSsh).port).toBeUndefined();
    for (const port of [0, 65_536, "22", 22.5]) {
      expect(() => sshActionSchema.parse({ ...validSsh, port })).toThrow();
    }
  });
});

describe("databaseActionSchema host:port range", () => {
  const validDb = {
    type: "database" as const,
    engine: "postgresql" as const,
    host: "db.example.com",
    database: "app",
    query: "SELECT 1",
  };

  it("accepts a host with an in-range embedded port", () => {
    expect(databaseActionSchema.parse({ ...validDb, host: "db.example.com:65535" }).host).toBe(
      "db.example.com:65535",
    );
  });

  it.each(["db.example.com:70000", "db.example.com:0", "db.example.com:99999"])(
    "rejects %s (embedded port out of range)",
    (host) => {
      expect(() => databaseActionSchema.parse({ ...validDb, host })).toThrow();
    },
  );

  it("still accepts a bare host without a port", () => {
    expect(databaseActionSchema.parse(validDb).host).toBe("db.example.com");
  });
});

describe("URL scheme boundary validation", () => {
  const validHttp = {
    type: "http" as const,
    method: "GET" as const,
    url: "https://api.github.com/user",
    injection: { type: "bearer" as const },
  };

  it.each(["javascript:alert(1)", "file:///etc/passwd", "ftp://host/x"])(
    "httpActionSchema rejects %s",
    (url) => {
      expect(() => httpActionSchema.parse({ ...validHttp, url })).toThrow();
    },
  );

  it("httpActionSchema accepts loopback http (core validateUrl allows it)", () => {
    expect(httpActionSchema.parse({ ...validHttp, url: "http://127.0.0.1:8080/x" }).url).toBe(
      "http://127.0.0.1:8080/x",
    );
  });

  it("mcpServerConfigSchema rejects a non-http(s) downstream URL", () => {
    expect(() =>
      mcpServerConfigSchema.parse({
        server_name: "downstream",
        transport: "http",
        url: "ftp://host/mcp",
      }),
    ).toThrow();
  });

  it("mcpServerConfigSchema accepts an https downstream URL", () => {
    const parsed = mcpServerConfigSchema.parse({
      server_name: "downstream",
      transport: "http",
      url: "https://mcp.example.com/mcp",
    });
    expect(parsed.url).toBe("https://mcp.example.com/mcp");
  });
});

describe("httpActionSchema headers validation", () => {
  const validHttp = {
    type: "http" as const,
    method: "GET" as const,
    url: "https://api.github.com/user",
    injection: { type: "bearer" as const },
  };

  it("accepts normal headers", () => {
    const parsed = httpActionSchema.parse({
      ...validHttp,
      headers: { Accept: "application/json", "X-Request-Id": "abc-123" },
    });
    expect(parsed.headers?.Accept).toBe("application/json");
  });

  it("rejects a header name with invalid characters", () => {
    expect(() => httpActionSchema.parse({ ...validHttp, headers: { "Bad Name:": "x" } })).toThrow();
  });

  it("rejects a header value smuggling CR/LF", () => {
    expect(() =>
      httpActionSchema.parse({ ...validHttp, headers: { "X-Test": "a\r\nInjected: 1" } }),
    ).toThrow();
  });

  it("rejects a header value containing NUL", () => {
    expect(() => httpActionSchema.parse({ ...validHttp, headers: { "X-Test": "a\0b" } })).toThrow();
  });

  it("rejects an oversized header value", () => {
    expect(() =>
      httpActionSchema.parse({ ...validHttp, headers: { "X-Test": "v".repeat(8193) } }),
    ).toThrow();
  });

  it("rejects more than 64 headers", () => {
    const headers = Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`X-H${i}`, "v"]));
    expect(() => httpActionSchema.parse({ ...validHttp, headers })).toThrow();
  });
});

describe("auditChainAnchorSchema", () => {
  const validAnchor = {
    format: "harpoc-audit-anchor/1",
    vault_id: "9f1c2e34-0000-4000-8000-000000000000",
    last_id: 4213,
    timestamp: 1784306411000,
    row_hmac: "a".repeat(64),
  };

  it("parses a valid anchor", () => {
    expect(auditChainAnchorSchema.parse(validAnchor)).toEqual(validAnchor);
  });

  it("round-trips through JSON", () => {
    const parsed = auditChainAnchorSchema.parse(JSON.parse(JSON.stringify(validAnchor)));
    expect(parsed).toEqual(validAnchor);
  });

  it("rejects a wrong format literal", () => {
    expect(() =>
      auditChainAnchorSchema.parse({ ...validAnchor, format: "harpoc-audit-anchor/2" }),
    ).toThrow();
    expect(() => auditChainAnchorSchema.parse({ ...validAnchor, format: "anchor" })).toThrow();
  });

  it.each(["format", "vault_id", "last_id", "timestamp", "row_hmac"] as const)(
    "rejects a missing %s field",
    (field) => {
      const partial = Object.fromEntries(
        Object.entries(validAnchor).filter(([key]) => key !== field),
      );
      expect(() => auditChainAnchorSchema.parse(partial)).toThrow();
    },
  );

  it("rejects unknown extra keys (strict)", () => {
    expect(() => auditChainAnchorSchema.parse({ ...validAnchor, extra: 1 })).toThrow();
  });

  it("rejects an uppercase row_hmac", () => {
    expect(() =>
      auditChainAnchorSchema.parse({ ...validAnchor, row_hmac: "A".repeat(64) }),
    ).toThrow();
  });

  it("rejects a short or long row_hmac", () => {
    expect(() =>
      auditChainAnchorSchema.parse({ ...validAnchor, row_hmac: "a".repeat(63) }),
    ).toThrow();
    expect(() =>
      auditChainAnchorSchema.parse({ ...validAnchor, row_hmac: "a".repeat(65) }),
    ).toThrow();
  });

  it("rejects non-hex characters in row_hmac", () => {
    expect(() =>
      auditChainAnchorSchema.parse({ ...validAnchor, row_hmac: "g".repeat(64) }),
    ).toThrow();
  });

  it("rejects a non-integer or non-positive last_id", () => {
    expect(() => auditChainAnchorSchema.parse({ ...validAnchor, last_id: 1.5 })).toThrow();
    expect(() => auditChainAnchorSchema.parse({ ...validAnchor, last_id: 0 })).toThrow();
    expect(() => auditChainAnchorSchema.parse({ ...validAnchor, last_id: "4213" })).toThrow();
  });

  it("rejects an empty vault_id", () => {
    expect(() => auditChainAnchorSchema.parse({ ...validAnchor, vault_id: "" })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// v1.3 extended-context action schemas
// ---------------------------------------------------------------------------

describe("v1.3 action schemas", () => {
  it("accepts a minimal smtp action and applies defaults", () => {
    const a = smtpActionSchema.parse({
      type: "smtp",
      host: "smtp.example.com",
      from: "bot@example.com",
      to: ["ops@example.com"],
      subject: "hi",
      text: "body",
    });
    expect(a.security).toBe("tls");
  });
  it("refuses an smtp action with neither text nor html", () => {
    expect(() =>
      smtpActionSchema.parse({
        type: "smtp",
        host: "h",
        from: "a@b.c",
        to: ["d@e.f"],
        subject: "s",
      }),
    ).toThrow();
  });
  it("refuses envelope-shadowing extra headers", () => {
    for (const k of [
      "From",
      "to",
      "Subject",
      "content-type",
      "MIME-Version",
      "Date",
      "Message-ID",
      "Cc",
      "bcc",
    ]) {
      expect(() =>
        smtpActionSchema.parse({
          type: "smtp",
          host: "h",
          from: "a@b.c",
          to: ["d@e.f"],
          subject: "s",
          text: "x",
          headers: { [k]: "v" },
        }),
      ).toThrow();
    }
  });
  it("refuses relative and control-char attachment paths", () => {
    const base = { type: "smtp", host: "h", from: "a@b.c", to: ["d@e.f"], subject: "s", text: "x" };
    expect(() =>
      smtpActionSchema.parse({ ...base, attachments: [{ path: "rel/file.txt" }] }),
    ).toThrow();
    expect(() =>
      smtpActionSchema.parse({ ...base, attachments: [{ path: "C:/x\n.txt" }] }),
    ).toThrow();
  });
  it("imap: structured search only, closed flag enum, uid caps", () => {
    expect(
      imapActionSchema.parse({
        type: "imap",
        host: "mail.example.com",
        operation: { kind: "search", unseen: true, since: "2026-08-01" },
      }).mailbox,
    ).toBe("INBOX");
    expect(() =>
      imapActionSchema.parse({
        type: "imap",
        host: "h",
        operation: { kind: "store", uids: [1], add_flags: ["\\Recent"] },
      }),
    ).toThrow(); // not in the closed enum
    expect(() =>
      imapActionSchema.parse({
        type: "imap",
        host: "h",
        operation: {
          kind: "fetch",
          uids: Array.from({ length: 101 }, (_, i) => i + 1),
          parts: "headers",
        },
      }),
    ).toThrow();
  });
  it("imap: optional account (the XOAUTH2 identity) must be an email address", () => {
    expect(
      imapActionSchema.parse({
        type: "imap",
        host: "mail.example.com",
        operation: { kind: "search", unseen: true },
        account: "agent@example.com",
      }).account,
    ).toBe("agent@example.com");
    expect(
      imapActionSchema.parse({
        type: "imap",
        host: "mail.example.com",
        operation: { kind: "search", unseen: true },
      }),
    ).not.toHaveProperty("account");
    expect(() =>
      imapActionSchema.parse({
        type: "imap",
        host: "mail.example.com",
        operation: { kind: "search", unseen: true },
        account: "not-an-email",
      }),
    ).toThrow();
  });
  it("websocket: wss ok, ws non-loopback refused, ws loopback ok, collect bounds", () => {
    expect(() =>
      websocketActionSchema.parse({
        type: "websocket",
        url: "ws://example.com/x",
        injection: { type: "bearer" },
      }),
    ).toThrow();
    websocketActionSchema.parse({
      type: "websocket",
      url: "ws://127.0.0.1:9/x",
      injection: { type: "bearer" },
    });
    expect(() =>
      websocketActionSchema.parse({
        type: "websocket",
        url: "wss://a.b/x",
        injection: { type: "bearer" },
        collect: { max_messages: 101 },
      }),
    ).toThrow();
  });
  it("sftp: local_path required for upload/download, refused for list; control chars refused", () => {
    expect(() =>
      sftpActionSchema.parse({
        type: "sftp",
        host: "h",
        user: "u",
        operation: "upload",
        remote_path: "/r",
      }),
    ).toThrow();
    expect(() =>
      sftpActionSchema.parse({
        type: "sftp",
        host: "h",
        user: "u",
        operation: "list",
        remote_path: "/r",
        local_path: "/l",
      }),
    ).toThrow();
    expect(() =>
      sftpActionSchema.parse({
        type: "sftp",
        host: "h",
        user: "u",
        operation: "list",
        remote_path: "/r\nrm x",
      }),
    ).toThrow();
  });
  it("sftp: accepts an optional port in range and refuses 0, 65536 and a string", () => {
    const validSftp = {
      type: "sftp" as const,
      host: "sftp.example.com",
      user: "deploy",
      operation: "list" as const,
      remote_path: "/srv/reports",
    };
    expect(sftpActionSchema.parse({ ...validSftp, port: 2222 }).port).toBe(2222);
    expect(sftpActionSchema.parse(validSftp).port).toBeUndefined();
    for (const port of [0, 65_536, "22", 22.5]) {
      expect(() => sftpActionSchema.parse({ ...validSftp, port })).toThrow();
    }
  });
  it("docker_registry: image reference validated, timeout cap 30 min", () => {
    dockerRegistryActionSchema.parse({
      type: "docker_registry",
      operation: "pull",
      image: "registry.example.com:5000/team/app:1.2",
    });
    expect(() =>
      dockerRegistryActionSchema.parse({
        type: "docker_registry",
        operation: "pull",
        image: "reg/app:1.2",
        timeout_ms: 1_800_001,
      }),
    ).toThrow();
  });
  it("database per-engine refinement matrix", () => {
    const sql = {
      type: "database",
      engine: "postgresql",
      host: "db",
      database: "d",
      query: "select 1",
    };
    databaseActionSchema.parse(sql);
    expect(() => databaseActionSchema.parse({ ...sql, command: ["PING"] })).toThrow();
    databaseActionSchema.parse({
      type: "database",
      engine: "redis",
      host: "r",
      database: "0",
      command: ["GET", "k"],
    });
    expect(() =>
      databaseActionSchema.parse({
        type: "database",
        engine: "redis",
        host: "r",
        database: "0",
        query: "GET k",
      }),
    ).toThrow();
    databaseActionSchema.parse({
      type: "database",
      engine: "mongodb",
      host: "m",
      database: "app",
      command: { find: "users", limit: 1 },
    });
    expect(() =>
      databaseActionSchema.parse({
        type: "database",
        engine: "mongodb",
        host: "m",
        database: "app",
        command: { find: "users" },
        params: [1],
      }),
    ).toThrow();
  });
  it("redis requires a non-negative integer database index", () => {
    for (const database of ["app", "-1"]) {
      expect(() =>
        databaseActionSchema.parse({
          type: "database",
          engine: "redis",
          host: "r",
          database,
          command: ["PING"],
        }),
      ).toThrow("non-negative integer index");
    }
    databaseActionSchema.parse({
      type: "database",
      engine: "redis",
      host: "r",
      database: "12",
      command: ["PING"],
    });
    databaseActionSchema.parse({
      type: "database",
      engine: "mongodb",
      host: "m",
      database: "admin",
      command: { ping: 1 },
    });
  });
  it("policy input gains recipient allowlist + imap_read_only with replace defaults", () => {
    const p = injectionPolicyInputSchema.parse({});
    expect(p.smtp_recipient_allowlist).toEqual([]);
    expect(p.imap_read_only).toBe(false);
    expect(() => injectionPolicyInputSchema.parse({ smtp_recipient_allowlist: ["*@*"] })).toThrow(); // wildcard domain refused
    injectionPolicyInputSchema.parse({
      smtp_recipient_allowlist: ["ops@example.com", "*@example.com"],
    });
  });
});

// ---------------------------------------------------------------------------
// Agent governance schemas (v1.4)
// ---------------------------------------------------------------------------

describe("agentNameSchema", () => {
  it("accepts cli-user, web-ui and a_b", () => {
    for (const name of ["cli-user", "web-ui", "a_b"]) {
      expect(agentNameSchema.parse(name)).toBe(name);
    }
  });

  it("refuses a name with a space", () => {
    expect(() => agentNameSchema.parse("with space")).toThrow();
  });

  it("refuses a name with a dot", () => {
    expect(() => agentNameSchema.parse("a.b")).toThrow();
  });

  it("refuses a name longer than 255 characters", () => {
    expect(() => agentNameSchema.parse("a".repeat(256))).toThrow();
  });

  it("accepts a name of exactly 255 characters", () => {
    expect(agentNameSchema.parse("a".repeat(255))).toBe("a".repeat(255));
  });
});

describe("registerAgentInputSchema", () => {
  it("accepts a minimal valid input", () => {
    const result = registerAgentInputSchema.parse({ name: "claude-code" });
    expect(result.name).toBe("claude-code");
    expect(result.description).toBeUndefined();
    expect(result.owner).toBeUndefined();
  });

  it("accepts a description up to 1024 characters", () => {
    const description = "a".repeat(1024);
    const result = registerAgentInputSchema.parse({ name: "claude-code", description });
    expect(result.description).toBe(description);
  });

  it("refuses a description over 1024 characters", () => {
    expect(() =>
      registerAgentInputSchema.parse({ name: "claude-code", description: "a".repeat(1025) }),
    ).toThrow();
  });

  it("accepts an owner up to 255 characters", () => {
    const owner = "a".repeat(255);
    const result = registerAgentInputSchema.parse({ name: "claude-code", owner });
    expect(result.owner).toBe(owner);
  });

  it("refuses an owner over 255 characters", () => {
    expect(() =>
      registerAgentInputSchema.parse({ name: "claude-code", owner: "a".repeat(256) }),
    ).toThrow();
  });
});

describe("updateAgentInputSchema", () => {
  it("accepts an empty update and a description/owner update", () => {
    expect(updateAgentInputSchema.parse({})).toEqual({});
    const result = updateAgentInputSchema.parse({ description: "d", owner: "o" });
    expect(result.description).toBe("d");
    expect(result.owner).toBe("o");
  });

  it("refuses a description over the cap", () => {
    expect(() => updateAgentInputSchema.parse({ description: "a".repeat(1025) })).toThrow();
  });
});

describe("setAgentPermissionsInputSchema", () => {
  it("accepts an empty permissions array", () => {
    const result = setAgentPermissionsInputSchema.parse({ permissions: [] });
    expect(result.permissions).toEqual([]);
  });

  it("refuses an unknown permission", () => {
    expect(() => setAgentPermissionsInputSchema.parse({ permissions: ["manage"] })).toThrow();
  });

  it("accepts an expires_at", () => {
    const result = setAgentPermissionsInputSchema.parse({ permissions: ["read"], expires_at: 1 });
    expect(result.expires_at).toBe(1);
  });
});

describe("listAgentsQuerySchema", () => {
  it("accepts an empty query and a status filter", () => {
    expect(listAgentsQuerySchema.parse({})).toEqual({});
    expect(listAgentsQuerySchema.parse({ status: "active" }).status).toBe("active");
  });

  it("refuses an unknown status", () => {
    expect(() => listAgentsQuerySchema.parse({ status: "disabled" })).toThrow();
  });
});

describe("listTokensQuerySchema", () => {
  it("refuses status: 'live'", () => {
    expect(() => listTokensQuerySchema.parse({ status: "live" })).toThrow();
  });

  it("accepts a valid status filter and agent name", () => {
    const result = listTokensQuerySchema.parse({ status: "active", agent: "claude-code" });
    expect(result.status).toBe("active");
    expect(result.agent).toBe("claude-code");
  });
});

describe("connectionConfigSchema", () => {
  const CA = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

  it("accepts a git group carrying a CA PEM", () => {
    const parsed = connectionConfigSchema.safeParse({ git: { ca_pem: CA } });
    expect(parsed.success).toBe(true);
    if (parsed.success) expect(parsed.data.git).toEqual({ ca_pem: CA });
  });

  it("refuses a git group without ca_pem", () => {
    expect(connectionConfigSchema.safeParse({ git: {} }).success).toBe(false);
  });

  it("refuses an empty config, naming all four groups", () => {
    const parsed = connectionConfigSchema.safeParse({});
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.issues[0]?.message).toBe(
        "connection config must set at least one of database, ssh, mail or git",
      );
    }
  });

  it("still accepts each existing group alone", () => {
    expect(connectionConfigSchema.safeParse({ database: { tls_mode: "require" } }).success).toBe(
      true,
    );
    expect(
      connectionConfigSchema.safeParse({ ssh: { known_hosts: ["h ssh-ed25519 AAAA"] } }).success,
    ).toBe(true);
    expect(connectionConfigSchema.safeParse({ mail: { tls: false } }).success).toBe(true);
  });
});
