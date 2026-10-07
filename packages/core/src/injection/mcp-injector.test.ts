import { afterEach, describe, expect, it, vi } from "vitest";
import type { InjectionPolicy, McpAction, McpServerConfig } from "@harpoc/shared";
import { ErrorCode, MAX_MCP_RESULT_BYTES } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { POLICY, SECRET, STDIO_CONFIG, mcpAction } from "./__fixtures__/mcp-downstream.js";
import { McpInjector } from "./mcp-injector.js";
import { McpConnectionRegistry } from "./mcp-registry.js";

let registry: McpConnectionRegistry;
let injector: McpInjector;

function freshInjector(): void {
  registry = new McpConnectionRegistry(null);
  injector = new McpInjector(null, registry);
}
freshInjector();

function run(
  action: McpAction,
  {
    config = STDIO_CONFIG,
    policy = POLICY,
    secret = SECRET,
    secretId = "secret-1",
  }: {
    config?: McpServerConfig;
    policy?: InjectionPolicy;
    secret?: string;
    secretId?: string;
  } = {},
) {
  return injector.executeWithSecret(
    action,
    new Uint8Array(Buffer.from(secret, "utf8")),
    policy,
    config,
    secretId,
  );
}

afterEach(async () => {
  await registry.closeAll("test_cleanup");
  freshInjector();
});

describe("McpInjector — validation", () => {
  it("rejects a server name that does not match the configured one", async () => {
    const acquireSpy = vi.spyOn(registry, "acquire");
    await expect(run(mcpAction("echo", { server: "other-mcp" }))).rejects.toMatchObject({
      code: ErrorCode.MCP_SERVER_MISMATCH,
    });
    expect(acquireSpy).not.toHaveBeenCalled();
  });

  it("fail-safe denies stdio launch when the command allowlist is empty", async () => {
    const acquireSpy = vi.spyOn(registry, "acquire");
    await expect(
      run(mcpAction("echo"), { policy: { ...POLICY, command_allowlist: [] } }),
    ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });
    expect(acquireSpy).not.toHaveBeenCalled();
  });

  it("denies an http endpoint not on the URL allowlist", async () => {
    const acquireSpy = vi.spyOn(registry, "acquire");
    await expect(
      run(mcpAction("echo"), {
        config: {
          server_name: "test-mcp",
          transport: "http",
          protocol: "2025-11-25",
          url: "https://evil.example.com/mcp",
        },
        policy: { ...POLICY, url_allowlist: ["https://good.example.com/*"] },
      }),
    ).rejects.toMatchObject({ code: ErrorCode.URL_NOT_ALLOWED });
    expect(acquireSpy).not.toHaveBeenCalled();
  });

  it("rejects a plaintext http endpoint on a non-loopback host", async () => {
    const acquireSpy = vi.spyOn(registry, "acquire");
    await expect(
      run(mcpAction("echo"), {
        config: {
          server_name: "test-mcp",
          transport: "http",
          protocol: "2025-11-25",
          url: "http://api.example.com/mcp",
        },
        policy: { ...POLICY, url_allowlist: ["http://api.example.com/*"] },
      }),
    ).rejects.toMatchObject({ code: ErrorCode.URL_HTTPS_REQUIRED });
    expect(acquireSpy).not.toHaveBeenCalled();
  });

  /**
   * T9: every denial case above starts from a cold registry, so moving target
   * validation into `establish()` — a plausible optimization, since that is
   * where the command is used — would keep a *live* connection serving calls
   * whose target the policy no longer allows. Complete mediation means the
   * check runs on the reuse path too.
   */
  describe("target validation runs on a warm connection (complete mediation)", () => {
    it("a command dropped from the allowlist stops serving an already-spawned server", async () => {
      const before = await run(mcpAction("pid"));
      expect(registry.get("secret-1")).toBeDefined();

      await expect(
        run(mcpAction("echo"), { policy: { ...POLICY, command_allowlist: [] } }),
      ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });

      // Control: the refusal is the policy's, not a dead connection's — the
      // same live server still answers when the allowlist permits it.
      const after = await run(mcpAction("pid"));
      expect(after.content).toEqual(before.content);
    });

    it("the check is not skipped for a server that answered a moment ago", async () => {
      await run(mcpAction("echo"));
      const live = registry.get("secret-1");
      expect(live).toBeDefined();

      await expect(
        run(mcpAction("echo"), { policy: { ...POLICY, command_allowlist: ["/usr/bin/other"] } }),
      ).rejects.toMatchObject({ code: ErrorCode.COMMAND_NOT_ALLOWED });

      // The connection was not torn down by the refusal — it is the *call*
      // that is refused, so the next permitted call still reuses it.
      expect(registry.get("secret-1")).toBe(live);
    });
  });
});

describe("McpInjector — tool call forwarding", () => {
  it("forwards a tool call and returns the sanitized result", async () => {
    const result = await run(mcpAction("echo", { arguments: { visibility: "public" } }));
    expect(result.type).toBe("mcp");
    expect(result.content).toEqual([
      { type: "text", text: JSON.stringify({ visibility: "public" }) },
    ]);
    expect(result.is_error).toBeUndefined();
  });

  it("passes a downstream tool-level error through in-band", async () => {
    const result = await run(mcpAction("error-tool"));
    expect(result.is_error).toBe(true);
  });

  it("maps a downstream protocol error to MCP_PROTOCOL_ERROR", async () => {
    await expect(run(mcpAction("no-such-tool"))).rejects.toMatchObject({
      code: ErrorCode.MCP_PROTOCOL_ERROR,
    });
  });

  it("times out a slow tool without killing the server", async () => {
    await expect(run(mcpAction("slow", { timeout_ms: 300 }))).rejects.toMatchObject({
      code: ErrorCode.MCP_TIMEOUT,
    });
    // Server survives: the same connection answers the next call.
    expect(registry.get("secret-1")).toBeDefined();
    const result = await run(mcpAction("echo", { arguments: { after: "timeout" } }));
    expect(result.content).toEqual([{ type: "text", text: JSON.stringify({ after: "timeout" }) }]);
  });
});

describe("McpInjector — output sanitization (I2b)", () => {
  it("redacts the credential echoed from the downstream env", async () => {
    const result = await run(mcpAction("leak-env"));
    const text = JSON.stringify(result);
    expect(text).not.toContain(SECRET);
    expect(text).toContain("[REDACTED]");
  });

  it("redacts a base64 encoding of the credential", async () => {
    const result = await run(mcpAction("leak-env-b64"));
    const text = JSON.stringify(result);
    expect(text).not.toContain(Buffer.from(SECRET, "utf8").toString("base64"));
    expect(text).toContain("[REDACTED]");
  });

  it("redacts the credential inside structured_content leaves", async () => {
    const result = await run(mcpAction("leak-structured"));
    expect(result.structured_content).toEqual({ nested: { secret: "[REDACTED]" } });
  });

  it("caps an oversized result and flags truncation", async () => {
    const result = await run(mcpAction("big"));
    expect(result.truncated).toBe(true);
    expect(result.content).toEqual([]);
    expect(Buffer.byteLength(JSON.stringify(result))).toBeLessThanOrEqual(MAX_MCP_RESULT_BYTES);
  });

  it("drops structured_content first, keeping every content block", async () => {
    const result = await run(mcpAction("big-structured"));
    expect(result.truncated).toBe(true);
    expect(result.structured_content).toBeUndefined();
    expect(result.content).toEqual([
      { type: "text", text: "keep-1" },
      { type: "text", text: "keep-2" },
    ]);
  });

  it("then pops trailing content blocks, keeping the leading ones", async () => {
    const result = await run(mcpAction("big-tail"));
    expect(result.truncated).toBe(true);
    expect(result.content).toEqual([{ type: "text", text: "lead" }]);
    expect(Buffer.byteLength(JSON.stringify(result))).toBeLessThanOrEqual(MAX_MCP_RESULT_BYTES);
  });
});

/** The names libuv copies from the parent into a win32 child environment that lacks them. */
const WIN32_LIBUV_REQUIRED_ENV = [
  "HOMEDRIVE",
  "HOMEPATH",
  "LOGONSERVER",
  "SYSTEMDRIVE",
  "SYSTEMROOT",
  "TEMP",
  "USERDOMAIN",
  "USERNAME",
  "USERPROFILE",
  "WINDIR",
];

describe("McpInjector — the stdio child's environment (§4.5.3 layer 3)", () => {
  const AMBIENT = "HARPOC_MCP_AMBIENT";
  const ALLOWED = "HARPOC_MCP_ALLOWED";

  afterEach(() => {
    Reflect.deleteProperty(process.env, AMBIENT);
    Reflect.deleteProperty(process.env, ALLOWED);
  });

  function childEnvKeys(result: { content?: unknown }): string[] {
    const [first] = result.content as { type: string; text: string }[];
    return JSON.parse((first as { text: string }).text) as string[];
  }

  function toleratedKeys(...allowlisted: string[]): Set<string> {
    return new Set([
      "DOWNSTREAM_TOKEN",
      "PATH",
      ...allowlisted,
      ...(process.platform === "win32" ? WIN32_LIBUV_REQUIRED_ENV : []),
      ...(process.platform === "darwin" ? ["__CF_USER_TEXT_ENCODING"] : []),
    ]);
  }

  it("hands the downstream child a built environment, not the vault's own", async () => {
    process.env[AMBIENT] = "ambient-value";
    const keys = childEnvKeys(await run(mcpAction("env-keys")));
    expect(keys).not.toContain(AMBIENT);
    expect(keys).toEqual(expect.arrayContaining(["DOWNSTREAM_TOKEN", "PATH"]));
    const tolerated = toleratedKeys();
    expect(keys.filter((k) => !tolerated.has(k))).toEqual([]);
  });

  it("passes an env_allowlist entry through to the downstream child", async () => {
    process.env[ALLOWED] = "allowed-value";
    const keys = childEnvKeys(
      await run(mcpAction("env-keys"), { policy: { ...POLICY, env_allowlist: [ALLOWED] } }),
    );
    expect(keys).toEqual(expect.arrayContaining(["DOWNSTREAM_TOKEN", "PATH", ALLOWED]));
    const tolerated = toleratedKeys(ALLOWED);
    expect(keys.filter((k) => !tolerated.has(k))).toEqual([]);
  });
});

describe("McpInjector — lifecycle (thesis §4.5.4)", () => {
  it("spawns on first use and reuses the server across calls", async () => {
    const first = await run(mcpAction("pid"));
    const second = await run(mcpAction("pid"));
    expect(first.content).toEqual(second.content);
  });

  it("a crash mid-call fails visibly with exit forensics and removes the entry", async () => {
    await run(mcpAction("echo"));
    expect(registry.get("secret-1")).toBeDefined();

    await expect(run(mcpAction("crash"))).rejects.toMatchObject({
      code: ErrorCode.MCP_SERVER_CRASHED,
      details: { server: "test-mcp", exit_code: 7, signal: null },
    });

    // Removed on crash — no auto-respawn.
    expect(registry.get("secret-1")).toBeUndefined();
  });

  it("respawns on the next invocation after a crash", async () => {
    const before = await run(mcpAction("pid"));
    await expect(run(mcpAction("crash"))).rejects.toMatchObject({
      code: ErrorCode.MCP_SERVER_CRASHED,
    });

    const after = await run(mcpAction("pid"));
    expect(after.content).not.toEqual(before.content);
  });

  it("coalesces concurrent first calls onto a single spawn", async () => {
    const [a, b] = await Promise.all([run(mcpAction("pid")), run(mcpAction("pid"))]);
    expect(a.content).toEqual(b.content);
  });

  it("terminates and respawns when the credential rotates", async () => {
    const before = await run(mcpAction("pid"));
    const after = await run(mcpAction("pid"), { secret: "sk-rotated-value-999999" });
    expect(after.content).not.toEqual(before.content);
  });

  it("terminates and respawns when the config changes", async () => {
    const before = await run(mcpAction("pid"));
    const changed: McpServerConfig = { ...STDIO_CONFIG, working_directory: process.cwd() };
    const after = await run(mcpAction("pid"), { config: changed });
    expect(after.content).not.toEqual(before.content);
  });

  it("closeAll terminates live servers", async () => {
    await run(mcpAction("echo"));
    expect(registry.get("secret-1")).toBeDefined();
    await registry.closeAll("session_end");
    expect(registry.get("secret-1")).toBeUndefined();
  });

  it("killAllSync clears the registry without awaiting", async () => {
    await run(mcpAction("echo"));
    registry.killAllSync();
    expect(registry.get("secret-1")).toBeUndefined();
  });

  it("a handshake failure (the child exits before initialize) surfaces as MCP_CONNECT_FAILED and retries fresh", async () => {
    const dying: McpServerConfig = { ...STDIO_CONFIG, args: ["-e", "process.exit(1)"] };
    await expect(run(mcpAction("echo"), { config: dying })).rejects.toMatchObject({
      code: ErrorCode.MCP_CONNECT_FAILED,
    });
    // The failed connect did not poison the registry: a good config works.
    const result = await run(mcpAction("echo"));
    expect(result.type).toBe("mcp");
  });
});

// E70: the downstream echo is scrubbed out of the wire result, so the success
// row is the only surface on which the scrub is observable.
describe("McpInjector — sanitized rides the success row (E70)", () => {
  function lastDetail(log: ReturnType<typeof vi.fn>): Record<string, unknown> {
    const calls = log.mock.calls;
    const row = calls[calls.length - 1]?.[0] as { detail?: Record<string, unknown> };
    return row.detail ?? {};
  }

  it("stamps sanitized when the downstream echoed the credential", async () => {
    const log = vi.fn();
    const audited = new McpInjector({ log } as unknown as AuditLogger, registry);

    await audited.executeWithSecret(
      mcpAction("leak-env"),
      new Uint8Array(Buffer.from(SECRET, "utf8")),
      POLICY,
      STDIO_CONFIG,
      "secret-1",
    );

    expect(lastDetail(log)).toMatchObject({ sanitized: true });
  });

  it("leaves the key absent when the downstream echoed nothing", async () => {
    const log = vi.fn();
    const audited = new McpInjector({ log } as unknown as AuditLogger, registry);

    await audited.executeWithSecret(
      mcpAction("echo", { arguments: { visibility: "public" } }),
      new Uint8Array(Buffer.from(SECRET, "utf8")),
      POLICY,
      STDIO_CONFIG,
      "secret-1",
    );

    expect(lastDetail(log)).not.toHaveProperty("sanitized");
  });
});
