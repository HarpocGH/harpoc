import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { VaultApiToken } from "@harpoc/shared";

const { mockEngine } = vi.hoisted(() => ({
  mockEngine: {
    useSecret: vi.fn(),
    verifyToken: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn().mockResolvedValue(mockEngine),
}));

import { registerSecretUseCommand, summarizeResult } from "./use.js";

const HTTP_ARGS = ["--action", "http", "--url", "https://api.example.com/v1"];

function token(overrides: Partial<VaultApiToken> = {}): VaultApiToken {
  return {
    sub: "agent-1",
    vault_id: "vault-1",
    scope: ["use"],
    iat: 0,
    exp: 2_000_000_000,
    jti: "jti-1",
    ...overrides,
  };
}

describe("secret use — token-scoped path (D1)", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  const savedEnvToken = process.env.HARPOC_TOKEN;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
    mockEngine.useSecret.mockResolvedValue({ type: "http", status: 200, body: "ok" });
    mockEngine.verifyToken.mockReturnValue(token());
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errorSpy.mockRestore();
    logSpy.mockRestore();
    if (savedEnvToken === undefined) delete process.env.HARPOC_TOKEN;
    else process.env.HARPOC_TOKEN = savedEnvToken;
  });

  async function run(args: string[]): Promise<void> {
    const program = new Command();
    program.option("--vault-dir <path>", "Path to vault directory");
    const secret = program.command("secret");
    registerSecretUseCommand(secret);
    program.exitOverride();
    program.configureOutput({ writeErr: () => {} });
    await program.parseAsync(["node", "harpoc", "secret", "use", ...args]);
  }

  it("passes no caller when no token is supplied — the trusted local path is unchanged", async () => {
    await run(["secret://api-key", ...HTTP_ARGS]);
    expect(mockEngine.verifyToken).not.toHaveBeenCalled();
    expect(mockEngine.useSecret).toHaveBeenCalledWith(
      "secret://api-key",
      expect.objectContaining({ type: "http" }),
      undefined,
    );
  });

  it("verifies the token and attributes the call to the cli interface", async () => {
    await run(["secret://api-key", ...HTTP_ARGS, "--token", "jwt-value"]);
    expect(mockEngine.verifyToken).toHaveBeenCalledWith("jwt-value");
    expect(mockEngine.useSecret).toHaveBeenCalledWith(
      "secret://api-key",
      expect.objectContaining({ type: "http" }),
      { principal_type: "agent", principal_id: "agent-1", interface: "cli" },
    );
  });

  it("carries the token's principal type and project into the caller", async () => {
    mockEngine.verifyToken.mockReturnValue(
      token({ sub: "tool-7", principal_type: "tool", project: "api" }),
    );
    await run(["secret://api/api-key", ...HTTP_ARGS, "--token", "jwt-value"]);
    expect(mockEngine.useSecret).toHaveBeenCalledWith("secret://api/api-key", expect.anything(), {
      principal_type: "tool",
      principal_id: "tool-7",
      project: "api",
      interface: "cli",
    });
  });

  it("reads an ambient HARPOC_TOKEN when no flag is given (D8)", async () => {
    process.env.HARPOC_TOKEN = "env-jwt";
    await run(["secret://api-key", ...HTTP_ARGS]);
    expect(mockEngine.verifyToken).toHaveBeenCalledWith("env-jwt");
  });

  it("an explicit --token wins over an ambient HARPOC_TOKEN (D8 precedence)", async () => {
    process.env.HARPOC_TOKEN = "env-jwt";
    await run(["secret://api-key", ...HTTP_ARGS, "--token", "flag-jwt"]);
    expect(mockEngine.verifyToken).toHaveBeenCalledWith("flag-jwt");
    expect(mockEngine.verifyToken).toHaveBeenCalledTimes(1);
  });

  // A present-but-empty token must not degrade into the MORE privileged path.
  it("refuses an empty --token instead of silently using the trusted local path", async () => {
    await expect(run(["secret://api-key", ...HTTP_ARGS, "--token", ""])).rejects.toThrow(
      "process.exit",
    );
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("supplied but empty"));
    expect(mockEngine.verifyToken).not.toHaveBeenCalled();
    expect(mockEngine.useSecret).not.toHaveBeenCalled();
  });

  it("refuses an empty ambient HARPOC_TOKEN the same way", async () => {
    process.env.HARPOC_TOKEN = "";
    await expect(run(["secret://api-key", ...HTTP_ARGS])).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("HARPOC_TOKEN"));
    expect(mockEngine.useSecret).not.toHaveBeenCalled();
  });

  it("an absent HARPOC_TOKEN is still the trusted local path (the control)", async () => {
    delete process.env.HARPOC_TOKEN;
    await run(["secret://api-key", ...HTTP_ARGS]);
    expect(mockEngine.useSecret).toHaveBeenCalledWith(
      "secret://api-key",
      expect.anything(),
      undefined,
    );
  });

  it("documents the argv exposure its sibling token flags document", () => {
    const program = new Command();
    const secret = program.command("secret");
    registerSecretUseCommand(secret);
    const use = secret.commands.find((c) => c.name() === "use");
    const tokenOption = use?.options.find((o) => o.long === "--token");
    expect(tokenOption?.description).toMatch(/HARPOC_TOKEN/);
    expect(tokenOption?.description).toMatch(/visible to other local processes/i);
  });
});

describe("secret use — token denials refuse before the injection runs", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
    mockEngine.useSecret.mockResolvedValue({ type: "http", status: 200 });
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errorSpy.mockRestore();
    logSpy.mockRestore();
  });

  async function run(args: string[]): Promise<void> {
    const program = new Command();
    program.option("--vault-dir <path>", "Path to vault directory");
    const secret = program.command("secret");
    registerSecretUseCommand(secret);
    program.exitOverride();
    program.configureOutput({ writeErr: () => {} });
    await program.parseAsync(["node", "harpoc", "secret", "use", ...args]);
  }

  async function expectDenied(args: string[], code: ErrorCode): Promise<void> {
    await expect(run(args)).rejects.toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining(code));
    // The load-bearing half: the credential was never injected.
    expect(mockEngine.useSecret).not.toHaveBeenCalled();
    expect(mockEngine.destroy).toHaveBeenCalled();
  }

  it("refuses a token without the use permission", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ scope: ["read"] }));
    await expectDenied(
      ["secret://api-key", ...HTTP_ARGS, "--token", "jwt", "--json"],
      ErrorCode.ACCESS_DENIED,
    );
  });

  it("refuses a project-scoped token on another project's secret", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ project: "api" }));
    await expectDenied(
      ["secret://web/api-key", ...HTTP_ARGS, "--token", "jwt", "--json"],
      ErrorCode.ACCESS_DENIED,
    );
  });

  it("refuses a name-pattern-scoped token on a non-matching secret", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ secrets: ["db-*"] }));
    await expectDenied(
      ["secret://api-key", ...HTTP_ARGS, "--token", "jwt", "--json"],
      ErrorCode.ACCESS_DENIED,
    );
  });

  it("refuses an expired token (verification, not scope)", async () => {
    mockEngine.verifyToken.mockImplementation(() => {
      throw VaultError.tokenExpired();
    });
    await expectDenied(
      ["secret://api-key", ...HTTP_ARGS, "--token", "jwt", "--json"],
      ErrorCode.TOKEN_EXPIRED,
    );
  });

  it("refuses a revoked token", async () => {
    mockEngine.verifyToken.mockImplementation(() => {
      throw VaultError.tokenRevoked();
    });
    await expectDenied(
      ["secret://api-key", ...HTTP_ARGS, "--token", "jwt", "--json"],
      ErrorCode.TOKEN_REVOKED,
    );
  });

  it("allows the matching name pattern — the denials above are the scope, not a blanket refusal", async () => {
    mockEngine.verifyToken.mockReturnValue(token({ secrets: ["db-*"] }));
    await run(["secret://db-main", ...HTTP_ARGS, "--token", "jwt"]);
    expect(mockEngine.useSecret).toHaveBeenCalledWith(
      "secret://db-main",
      expect.anything(),
      expect.objectContaining({ interface: "cli" }),
    );
  });
});

// The command's flag→action mapping had no test file at all: `buildAction`
// mapped every one of the six contexts untested, and the only invocation of
// `secret use` anywhere in the repo was a platform-gated negative control.
describe("secret use — buildAction covers all six contexts", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
    mockEngine.useSecret.mockResolvedValue({ type: "http", status: 200 });
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errorSpy.mockRestore();
    logSpy.mockRestore();
  });

  async function run(args: string[]): Promise<void> {
    const program = new Command();
    program.option("--vault-dir <path>", "Path to vault directory");
    const secret = program.command("secret");
    registerSecretUseCommand(secret);
    program.exitOverride();
    program.configureOutput({ writeErr: () => {} });
    await program.parseAsync(["node", "harpoc", "secret", "use", ...args]);
  }

  function actionOf(): Record<string, unknown> {
    const call = mockEngine.useSecret.mock.calls[0] as unknown[] | undefined;
    if (!call) throw new Error("useSecret was never called");
    return call[1] as Record<string, unknown>;
  }

  it("http: method, url, injection, extra headers and body", async () => {
    await run([
      "secret://k",
      "--action",
      "http",
      "--method",
      "POST",
      "--url",
      "https://api.example.com/v1",
      "--injection",
      "header",
      "--header-name",
      "X-Api-Key",
      "--body",
      "payload",
      "--header",
      "X-Trace: abc",
    ]);
    expect(actionOf()).toMatchObject({
      type: "http",
      method: "POST",
      url: "https://api.example.com/v1",
      body: "payload",
      headers: { "X-Trace": "abc" },
      injection: { type: "header", header_name: "X-Api-Key" },
    });
  });

  it("process: command, repeated args, env var and cwd", async () => {
    await run([
      "secret://k",
      "--action",
      "process",
      "--command",
      "/usr/bin/printenv",
      "--arg",
      "TOKEN",
      "--arg",
      "HOME",
      "--env-var",
      "TOKEN",
      "--cwd",
      "/tmp",
    ]);
    expect(actionOf()).toMatchObject({
      type: "process",
      command: "/usr/bin/printenv",
      args: ["TOKEN", "HOME"],
      env_var: "TOKEN",
      working_directory: "/tmp",
    });
  });

  it("mcp: server, tool and JSON-parsed arguments", async () => {
    await run([
      "secret://k",
      "--action",
      "mcp",
      "--server",
      "downstream",
      "--tool",
      "reveal",
      "--arguments",
      '{"n":1}',
    ]);
    expect(actionOf()).toMatchObject({
      type: "mcp",
      server: "downstream",
      tool: "reveal",
      arguments: { n: 1 },
    });
  });

  it("mcp: malformed --arguments names the flag instead of failing in the schema", async () => {
    await expect(
      run(["secret://k", "--action", "mcp", "--server", "s", "--tool", "t", "--arguments", "{"]),
    ).rejects.toThrow("process.exit");
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("--arguments"));
    expect(mockEngine.useSecret).not.toHaveBeenCalled();
  });

  it("database: engine, host, numeric port, database, query and repeated params", async () => {
    await run([
      "secret://k",
      "--action",
      "database",
      "--engine",
      "postgresql",
      "--host",
      "db.internal",
      "--port",
      "5432",
      "--database",
      "app",
      "--query",
      "SELECT $1::int",
      "--param",
      "42",
    ]);
    expect(actionOf()).toMatchObject({
      type: "database",
      engine: "postgresql",
      host: "db.internal",
      port: 5432,
      database: "app",
      query: "SELECT $1::int",
      params: ["42"],
    });
  });

  it("git: operation, repository, args and cwd", async () => {
    await run([
      "secret://k",
      "--action",
      "git",
      "--operation",
      "clone",
      "--repository",
      "https://git.example.com/x.git",
      "--arg",
      "--depth=1",
      "--cwd",
      "/tmp/work",
    ]);
    expect(actionOf()).toMatchObject({
      type: "git",
      operation: "clone",
      repository: "https://git.example.com/x.git",
      args: ["--depth=1"],
      working_directory: "/tmp/work",
    });
  });

  it("ssh: host, user and command", async () => {
    await run([
      "secret://k",
      "--action",
      "ssh",
      "--host",
      "10.0.0.5",
      "--user",
      "deploy",
      "--command",
      "id -un",
    ]);
    expect(actionOf()).toMatchObject({
      type: "ssh",
      host: "10.0.0.5",
      user: "deploy",
      command: "id -un",
    });
  });

  it("--timeout-ms reaches every context that accepts it", async () => {
    const contexts: [string, string[]][] = [
      ["http", ["--url", "https://api.example.com/v1"]],
      ["process", ["--command", "/usr/bin/printenv", "--env-var", "TOKEN"]],
      ["mcp", ["--server", "s", "--tool", "t"]],
      [
        "database",
        ["--engine", "postgresql", "--host", "db.internal", "--database", "a", "--query", "SELECT"],
      ],
      ["git", ["--operation", "clone", "--repository", "https://git.example.com/x.git"]],
      ["ssh", ["--host", "10.0.0.5", "--user", "u", "--command", "id"]],
    ];
    for (const [action, args] of contexts) {
      vi.clearAllMocks();
      mockEngine.useSecret.mockResolvedValue({ type: "http", status: 200 });
      await run(["secret://k", "--action", action, ...args, "--timeout-ms", "5000"]);
      expect(actionOf()).toMatchObject({ type: action, timeout_ms: 5000 });
    }
  });

  it("a non-integer --timeout-ms names the flag", async () => {
    await expect(run(["secret://k", ...HTTP_ARGS, "--timeout-ms", "soon"])).rejects.toThrow(
      "process.exit",
    );
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("--timeout-ms"));
    expect(mockEngine.useSecret).not.toHaveBeenCalled();
  });
});

// v1.3: the five Extended Injection Contexts (smtp, imap, websocket, sftp,
// docker_registry) buildAction gained, plus --action-file. Mirrors the
// six-context describe block above: one happy case (flags in → exact
// action object out) and one schema refusal per context.
describe("secret use — buildAction covers the five v1.3 contexts", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
    mockEngine.useSecret.mockResolvedValue({ type: "http", status: 200 });
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errorSpy.mockRestore();
    logSpy.mockRestore();
  });

  async function run(args: string[]): Promise<void> {
    const program = new Command();
    program.option("--vault-dir <path>", "Path to vault directory");
    const secret = program.command("secret");
    registerSecretUseCommand(secret);
    program.exitOverride();
    program.configureOutput({ writeErr: () => {} });
    await program.parseAsync(["node", "harpoc", "secret", "use", ...args]);
  }

  function actionOf(): Record<string, unknown> {
    const call = mockEngine.useSecret.mock.calls[0] as unknown[] | undefined;
    if (!call) throw new Error("useSecret was never called");
    return call[1] as Record<string, unknown>;
  }

  it("smtp: host, from, repeated to, subject, text and security", async () => {
    await run([
      "secret://k",
      "--action",
      "smtp",
      "--host",
      "smtp.example.com",
      "--from",
      "alerts@example.com",
      "--to",
      "a@example.com",
      "--to",
      "b@example.com",
      "--subject",
      "Report",
      "--text",
      "body text",
      "--security",
      "starttls",
    ]);
    expect(actionOf()).toMatchObject({
      type: "smtp",
      host: "smtp.example.com",
      from: "alerts@example.com",
      to: ["a@example.com", "b@example.com"],
      subject: "Report",
      text: "body text",
      security: "starttls",
    });
  });

  it("smtp: a missing --to (min 1 recipient) is refused by the schema", async () => {
    await expect(
      run([
        "secret://k",
        "--action",
        "smtp",
        "--host",
        "smtp.example.com",
        "--from",
        "alerts@example.com",
        "--subject",
        "Report",
        "--text",
        "body text",
      ]),
    ).rejects.toThrow("process.exit");
    expect(mockEngine.useSecret).not.toHaveBeenCalled();
    // The refusal must come from the schema (recipient count), not from
    // --action itself being unrecognized — pins the real failure reason.
    expect(errorSpy).not.toHaveBeenCalledWith(expect.stringContaining("--action must be one of"));
  });

  it("imap: host, mailbox, and a fetch operation with repeated uids and parts", async () => {
    await run([
      "secret://k",
      "--action",
      "imap",
      "--host",
      "imap.example.com",
      "--mailbox",
      "Archive",
      "--operation",
      "fetch",
      "--uid",
      "1",
      "--uid",
      "2",
      "--parts",
      "headers",
    ]);
    expect(actionOf()).toMatchObject({
      type: "imap",
      host: "imap.example.com",
      mailbox: "Archive",
      operation: { kind: "fetch", uids: [1, 2], parts: "headers" },
    });
  });

  it("imap: a store operation with no --uid (min 1) is refused by the schema", async () => {
    await expect(
      run([
        "secret://k",
        "--action",
        "imap",
        "--host",
        "imap.example.com",
        "--operation",
        "store",
        "--add-flag",
        "\\Seen",
      ]),
    ).rejects.toThrow("process.exit");
    expect(mockEngine.useSecret).not.toHaveBeenCalled();
    expect(errorSpy).not.toHaveBeenCalledWith(expect.stringContaining("--action must be one of"));
  });

  it("websocket: url, injection, message, collect window and subprotocols", async () => {
    await run([
      "secret://k",
      "--action",
      "websocket",
      "--url",
      "wss://ws.example.com/socket",
      "--injection",
      "header",
      "--header-name",
      "X-Api-Key",
      "--message",
      "hello",
      "--collect-max",
      "3",
      "--collect-window",
      "1000",
      "--subprotocol",
      "chat",
    ]);
    expect(actionOf()).toMatchObject({
      type: "websocket",
      url: "wss://ws.example.com/socket",
      injection: { type: "header", header_name: "X-Api-Key" },
      message: "hello",
      collect: { max_messages: 3, window_ms: 1000 },
      subprotocols: ["chat"],
    });
  });

  it("websocket: a plain ws:// URL to a non-loopback host is refused by the schema", async () => {
    await expect(
      run(["secret://k", "--action", "websocket", "--url", "ws://ws.example.com/socket"]),
    ).rejects.toThrow("process.exit");
    expect(mockEngine.useSecret).not.toHaveBeenCalled();
    expect(errorSpy).not.toHaveBeenCalledWith(expect.stringContaining("--action must be one of"));
  });

  it("sftp: host, user, operation, remote and local paths", async () => {
    await run([
      "secret://k",
      "--action",
      "sftp",
      "--host",
      "sftp.example.com",
      "--user",
      "deploy",
      "--operation",
      "upload",
      "--remote",
      "/var/data/file.txt",
      "--local",
      "/tmp/file.txt",
    ]);
    expect(actionOf()).toMatchObject({
      type: "sftp",
      host: "sftp.example.com",
      user: "deploy",
      operation: "upload",
      remote_path: "/var/data/file.txt",
      local_path: "/tmp/file.txt",
    });
  });

  it("sftp: --local paired with a list operation is refused by the schema", async () => {
    await expect(
      run([
        "secret://k",
        "--action",
        "sftp",
        "--host",
        "sftp.example.com",
        "--user",
        "deploy",
        "--operation",
        "list",
        "--remote",
        "/var/data",
        "--local",
        "/tmp/x",
      ]),
    ).rejects.toThrow("process.exit");
    expect(mockEngine.useSecret).not.toHaveBeenCalled();
    expect(errorSpy).not.toHaveBeenCalledWith(expect.stringContaining("--action must be one of"));
  });

  it("docker_registry: operation and image", async () => {
    await run([
      "secret://k",
      "--action",
      "docker_registry",
      "--operation",
      "pull",
      "--image",
      "registry.example.com/team/app:latest",
    ]);
    expect(actionOf()).toMatchObject({
      type: "docker_registry",
      operation: "pull",
      image: "registry.example.com/team/app:latest",
    });
  });

  it("docker_registry: an invalid image reference is refused by the schema", async () => {
    await expect(
      run([
        "secret://k",
        "--action",
        "docker_registry",
        "--operation",
        "pull",
        "--image",
        "not a valid ref",
      ]),
    ).rejects.toThrow("process.exit");
    expect(mockEngine.useSecret).not.toHaveBeenCalled();
    expect(errorSpy).not.toHaveBeenCalledWith(expect.stringContaining("--action must be one of"));
  });
});

describe("secret use — --action-file", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  let tempDir: string;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
    mockEngine.useSecret.mockResolvedValue({ type: "imap", operation: "expunge", affected: 0 });
    tempDir = join(
      tmpdir(),
      `harpoc-use-action-file-${String(Date.now())}-${Math.random().toString(36).slice(2)}`,
    );
    mkdirSync(tempDir, { recursive: true });
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errorSpy.mockRestore();
    logSpy.mockRestore();
    rmSync(tempDir, { recursive: true, force: true });
  });

  async function run(args: string[]): Promise<void> {
    const program = new Command();
    program.option("--vault-dir <path>", "Path to vault directory");
    const secret = program.command("secret");
    registerSecretUseCommand(secret);
    program.exitOverride();
    program.configureOutput({ writeErr: () => {} });
    await program.parseAsync(["node", "harpoc", "secret", "use", ...args]);
  }

  function actionOf(): Record<string, unknown> {
    const call = mockEngine.useSecret.mock.calls[0] as unknown[] | undefined;
    if (!call) throw new Error("useSecret was never called");
    return call[1] as Record<string, unknown>;
  }

  it("round-trips a complete action document through the same schema buildAction feeds", async () => {
    const filePath = join(tempDir, "action.json");
    const action = {
      type: "imap",
      host: "imap.example.com",
      port: 993,
      mailbox: "INBOX",
      operation: { kind: "expunge" },
    };
    writeFileSync(filePath, JSON.stringify(action));
    await run(["secret://k", "--action-file", filePath]);
    expect(actionOf()).toEqual(action);
  });

  it("conflicts with an action-shaping flag, naming both in an INVALID_INPUT refusal", async () => {
    const filePath = join(tempDir, "action.json");
    writeFileSync(
      filePath,
      JSON.stringify({
        type: "imap",
        host: "imap.example.com",
        mailbox: "INBOX",
        operation: { kind: "expunge" },
      }),
    );
    await expect(
      run(["secret://k", "--action-file", filePath, "--url", "https://api.example.com"]),
    ).rejects.toThrow("process.exit");
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("INVALID_INPUT"));
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("--action-file"));
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("--url"));
    expect(mockEngine.useSecret).not.toHaveBeenCalled();
  });

  it("a nonexistent --action-file path is refused as INVALID_INPUT, not a crash", async () => {
    await expect(
      run(["secret://k", "--action-file", join(tempDir, "missing.json")]),
    ).rejects.toThrow("process.exit");
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("INVALID_INPUT"));
    expect(mockEngine.useSecret).not.toHaveBeenCalled();
  });

  it("malformed JSON in --action-file is refused as INVALID_INPUT", async () => {
    const filePath = join(tempDir, "bad.json");
    writeFileSync(filePath, "{not json");
    await expect(run(["secret://k", "--action-file", filePath])).rejects.toThrow("process.exit");
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("INVALID_INPUT"));
    expect(mockEngine.useSecret).not.toHaveBeenCalled();
  });

  it("--action-file alone (no other flags) is not a false-positive conflict", async () => {
    const filePath = join(tempDir, "action.json");
    writeFileSync(
      filePath,
      JSON.stringify({
        type: "docker_registry",
        operation: "pull",
        image: "registry.example.com/team/app:latest",
      }),
    );
    await run(["secret://k", "--action-file", filePath]);
    expect(mockEngine.useSecret).toHaveBeenCalled();
  });
});

describe("secret use — --action is a closed set", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
    mockEngine.useSecret.mockResolvedValue({ type: "http", status: 200 });
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errorSpy.mockRestore();
    logSpy.mockRestore();
  });

  async function run(args: string[]): Promise<void> {
    const program = new Command();
    program.option("--vault-dir <path>", "Path to vault directory");
    const secret = program.command("secret");
    registerSecretUseCommand(secret);
    program.exitOverride();
    program.configureOutput({ writeErr: () => {} });
    await program.parseAsync(["node", "harpoc", "secret", "use", ...args]);
  }

  // An unknown --action used to build an HTTP action silently, so the user saw
  // a complaint about a missing URL rather than about the flag they mistyped.
  it.each(["Process", "postgres", "HTTP", "sshh"])(
    "rejects --action %s by name instead of falling through to http",
    async (value) => {
      await expect(
        run(["secret://k", "--action", value, "--command", "/bin/true", "--env-var", "T"]),
      ).rejects.toThrow("process.exit");
      expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("--action must be one of"));
      expect(mockEngine.useSecret).not.toHaveBeenCalled();
    },
  );

  it("still defaults to http when --action is omitted entirely", async () => {
    await run(["secret://k", "--url", "https://api.example.com/v1"]);
    expect(mockEngine.useSecret).toHaveBeenCalledWith(
      "secret://k",
      expect.objectContaining({ type: "http" }),
      undefined,
    );
  });
});

describe("secret use — output shape and boundary sanitization", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.HARPOC_TOKEN;
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errorSpy.mockRestore();
    logSpy.mockRestore();
  });

  async function run(args: string[]): Promise<string> {
    const program = new Command();
    program.option("--vault-dir <path>", "Path to vault directory");
    const secret = program.command("secret");
    registerSecretUseCommand(secret);
    program.exitOverride();
    program.configureOutput({ writeErr: () => {} });
    await program.parseAsync(["node", "harpoc", "secret", "use", ...args]);
    return logSpy.mock.calls.map((c) => String(c[0])).join("\n");
  }

  it("--json prints the exact machine shape", async () => {
    mockEngine.useSecret.mockImplementation(() =>
      Promise.resolve({ type: "process", exit_code: 0, stdout: "hello\n", stderr: "" }),
    );
    const out = await run([
      "secret://k",
      "--action",
      "process",
      "--command",
      "/bin/echo",
      "--env-var",
      "T",
      "--json",
    ]);
    expect(JSON.parse(out)).toEqual({
      type: "process",
      exit_code: 0,
      stdout: "hello\n",
      stderr: "",
    });
  });

  it("without --json prints a readable summary, not JSON", async () => {
    mockEngine.useSecret.mockImplementation(() =>
      Promise.resolve({ type: "process", exit_code: 0, stdout: "hello\n", stderr: "" }),
    );
    const out = await run([
      "secret://k",
      "--action",
      "process",
      "--command",
      "/bin/echo",
      "--env-var",
      "T",
    ]);
    expect(() => JSON.parse(out)).toThrow();
    expect(out).toContain("exit_code");
    expect(out).toContain("hello");
  });

  it("applies the boundary pattern guard the REST route and MCP tool apply", async () => {
    const leaked = "Bearer abcdefghijklmnopqrstuvwxyz012345";
    mockEngine.useSecret.mockImplementation(() =>
      Promise.resolve({
        type: "http",
        status: 200,
        body: `{"echo":"${leaked}"}`,
        headers: { "x-echo": leaked },
      }),
    );
    const out = await run(["secret://k", ...HTTP_ARGS, "--json"]);
    expect(out).not.toContain(leaked);
    expect(out).toContain("[REDACTED]");
  });

  it("leaves benign output untouched (negative control)", async () => {
    mockEngine.useSecret.mockImplementation(() =>
      Promise.resolve({ type: "http", status: 200, body: '{"ok":true,"items":3}' }),
    );
    const out = await run(["secret://k", ...HTTP_ARGS, "--json"]);
    expect(out).toContain('{\\"ok\\":true,\\"items\\":3}');
    expect(out).not.toContain("[REDACTED]");
  });
});

describe("summarizeResult renders every context", () => {
  it("http keeps status and previews the body", () => {
    expect(summarizeResult({ type: "http", status: 204 })).toEqual({ type: "http", status: 204 });
    const withBody = summarizeResult({ type: "http", status: 200, body: "a".repeat(500) });
    expect(String(withBody.body)).toContain("chars total");
  });

  it("mcp reports the item count", () => {
    expect(summarizeResult({ type: "mcp", content: [{ type: "text", text: "x" }] })).toMatchObject({
      type: "mcp",
      content_items: 1,
    });
  });

  it("database reports row_count and field names", () => {
    expect(
      summarizeResult({
        type: "database",
        row_count: 1,
        rows: [{ answer: 42 }],
        fields: [{ name: "answer" }],
      }),
    ).toMatchObject({ type: "database", row_count: 1, fields: "answer" });
  });

  it("git and ssh surface the exit code", () => {
    expect(
      summarizeResult({
        type: "git",
        operation: "clone",
        exit_code: 0,
        stdout: "",
        stderr: "",
      }),
    ).toMatchObject({ type: "git", operation: "clone", exit_code: 0 });
    expect(summarizeResult({ type: "ssh", exit_code: 255, stdout: "", stderr: "" })).toMatchObject({
      type: "ssh",
      exit_code: 255,
    });
  });

  it("sftp surfaces the exit code", () => {
    expect(summarizeResult({ type: "sftp", exit_code: 1, stdout: "", stderr: "" })).toMatchObject({
      type: "sftp",
      exit_code: 1,
    });
  });
});
