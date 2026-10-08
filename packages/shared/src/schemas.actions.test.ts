import { describe, expect, it } from "vitest";

import {
  databaseActionSchema,
  httpActionSchema,
  injectionConfigSchema,
  mcpActionSchema,
  mcpServerConfigSchema,
  processActionSchema,
  sshActionSchema,
  useSecretActionSchema,
  useSecretBodySchema,
  useSecretRequestSchema,
} from "./schemas.js";

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

describe("useSecretBodySchema (REST POST /secrets/:handle/use body)", () => {
  const action = {
    type: "http",
    method: "GET",
    url: "https://api.example.com/x",
    injection: { type: "bearer" },
  };

  it("accepts { action } and nothing else", () => {
    expect(useSecretBodySchema.safeParse({ action }).success).toBe(true);
  });

  it("refuses a stray top-level key (strict)", () => {
    const result = useSecretBodySchema.safeParse({
      action,
      handle: "secret://k",
    });
    expect(result.success).toBe(false);
    if (!result.success)
      expect(result.error.issues[0]?.message).toContain('Unrecognized key: "handle"');
  });

  it("refuses a missing action, naming it", () => {
    const result = useSecretBodySchema.safeParse({});
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error.issues[0]?.path).toEqual(["action"]);
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

  it("rejects timeout_ms at 300_001 for an ssh action (the 5-minute norm)", () => {
    const parsed = sshActionSchema.safeParse({
      type: "ssh",
      host: "host.example.com",
      user: "deploy",
      command: "uptime",
      timeout_ms: 300_001,
    });
    expect(parsed.success).toBe(false);
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

  it.each(["javascript:alert(1)", "file:///etc/passwd"])("httpActionSchema rejects %s", (url) => {
    expect(() => httpActionSchema.parse({ ...validHttp, url })).toThrow();
  });

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
