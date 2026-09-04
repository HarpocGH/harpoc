import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { InjectionPolicy, McpAction, McpServerConfig } from "@harpoc/shared";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { McpInjector } from "./mcp-injector.js";
import { McpConnectionRegistry } from "./mcp-registry.js";

const NODE = process.execPath;
const SECRET = "sk-mcp-crash-supersecret-abcdef123456";

/**
 * Downstream server that echoes its injected credential to STDERR before
 * exiting — the "debug-logging accident" of M9. `stderr_tail` lands in the
 * durable `mcp.crash` audit row, which admin-scoped MCP clients can read and
 * which otherwise carries no path to any secret value.
 */
const CRASH_SERVER = `
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
function send(msg) { process.stdout.write(JSON.stringify(msg) + "\\n"); }
rl.on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") {
    send({ jsonrpc: "2.0", id: m.id, result: {
      protocolVersion: m.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "harpoc-crash-downstream", version: "1.0.0" },
    }});
  } else if (m.method === "tools/call") {
    if (m.params.name === "crash") {
      const token = process.env.DOWNSTREAM_TOKEN || "";
      process.stderr.write("FATAL config dump: token=" + token + "\\n");
      process.stderr.write("b64=" + Buffer.from(token).toString("base64") + "\\n");
      setTimeout(() => process.exit(7), 20);
      return;
    }
    send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: "ok" }] } });
  }
});
`;

const CONFIG: McpServerConfig = {
  server_name: "crash-mcp",
  transport: "stdio",
  command: NODE,
  args: ["-e", CRASH_SERVER],
  env_var: "DOWNSTREAM_TOKEN",
};

const POLICY: InjectionPolicy = {
  url_allowlist: [],
  command_allowlist: [NODE],
  env_allowlist: [],
  host_allowlist: [],
  response_mode: "filtered",
  response_header_allowlist: [],
  network_isolation: false,
  fs_isolation: false,
  smtp_recipient_allowlist: [],
  imap_read_only: false,
};

function action(tool: string): McpAction {
  return { type: "mcp", server: "crash-mcp", tool };
}

/** Downstream server that records its own pid so the test can probe liveness. */
function pidReportingServer(pidFile: string): string {
  return `
    require("node:fs").writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));
    ${CRASH_SERVER}
  `;
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitFor(predicate: () => boolean, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline && !predicate()) {
    await new Promise((r) => setTimeout(r, 25));
  }
}

interface LoggedEvent {
  eventType: string;
  detail?: Record<string, unknown>;
}

function recordingLogger(): { logger: AuditLogger; events: LoggedEvent[] } {
  const events: LoggedEvent[] = [];
  const logger = {
    log: vi.fn((options: LoggedEvent) => {
      events.push(options);
      return 1;
    }),
  } as unknown as AuditLogger;
  return { logger, events };
}

let registry: McpConnectionRegistry | undefined;

afterEach(async () => {
  await registry?.closeAll("test_cleanup");
  registry = undefined;
  vi.restoreAllMocks();
});

describe("McpInjector — crash audit detail redaction (M9)", () => {
  it("strips the injected credential from the stderr tail recorded on crash", async () => {
    const { logger, events } = recordingLogger();
    registry = new McpConnectionRegistry(logger);
    const injector = new McpInjector(logger, registry);

    await expect(
      injector.executeWithSecret(
        action("crash"),
        new Uint8Array(Buffer.from(SECRET, "utf8")),
        POLICY,
        CONFIG,
        "secret-crash",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.MCP_SERVER_CRASHED });

    const crash = events.find((e) => e.eventType === AuditEventType.MCP_CRASH);
    expect(crash).toBeDefined();
    const tail = String(crash?.detail?.stderr_tail ?? "");

    // The tail is recorded (the channel works) but carries no credential in
    // any of the encodings the sanitizer covers.
    expect(tail).toContain("FATAL config dump");
    expect(tail).not.toContain(SECRET);
    expect(tail).not.toContain(Buffer.from(SECRET).toString("base64"));
  }, 20_000);

  /**
   * T16: the 2 KiB cap on the recorded tail had never executed — both crash
   * cases used a downstream writing a handful of bytes — so a chatty (or
   * deliberately verbose) downstream could push an unbounded blob into a
   * durable audit row that admin-scoped MCP clients read.
   */
  it("keeps only the last 2 KiB of a large stderr burst", async () => {
    const { logger, events } = recordingLogger();
    registry = new McpConnectionRegistry(logger);
    const injector = new McpInjector(logger, registry);

    const noisy: McpServerConfig = {
      ...CONFIG,
      args: [
        "-e",
        `
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
function send(msg) { process.stdout.write(JSON.stringify(msg) + "\\n"); }
rl.on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") {
    send({ jsonrpc: "2.0", id: m.id, result: {
      protocolVersion: m.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "noisy-downstream", version: "1.0.0" },
    }});
  } else if (m.method === "tools/call") {
    process.stderr.write("HEAD_MARKER_ONLY_AT_THE_START\\n");
    process.stderr.write("x".repeat(20000) + "\\n");
    process.stderr.write("TAIL_MARKER_AT_THE_END\\n");
    setTimeout(() => process.exit(7), 30);
  }
});
`,
      ],
    };

    await expect(
      injector.executeWithSecret(
        action("crash"),
        new Uint8Array(Buffer.from(SECRET, "utf8")),
        POLICY,
        noisy,
        "secret-noisy",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.MCP_SERVER_CRASHED });

    const crash = events.find((e) => e.eventType === AuditEventType.MCP_CRASH);
    const tail = String(crash?.detail?.stderr_tail ?? "");

    expect(tail.length).toBeGreaterThan(0);
    expect(tail.length).toBeLessThanOrEqual(2048);
    // It is the *tail*: the newest lines survive, the oldest are dropped.
    expect(tail).toContain("TAIL_MARKER_AT_THE_END");
    expect(tail).not.toContain("HEAD_MARKER_ONLY_AT_THE_START");
  }, 20_000);
});

describe("McpConnectionRegistry — connect racing a seal (M8)", () => {
  it("tears the child down instead of publishing it into a cleared registry", async () => {
    registry = new McpConnectionRegistry(null);
    const reg = registry;

    const killSync = vi.fn();
    const close = vi.fn().mockResolvedValue(undefined);
    const dispose = vi.fn();

    // A connect that resolves only after the seal has walked the table.
    const acquired = reg.acquire("secret-1", async () => {
      reg.killAllSync();
      await new Promise((r) => setTimeout(r, 10));
      return {
        secretId: "secret-1",
        serverName: "late-mcp",
        transportKind: "stdio" as const,
        client: { close } as never,
        stdioTransport: { killSync } as never,
        dispose,
        state: "connecting" as const,
        crashed: false,
        credentialFingerprint: "f",
        configFingerprint: "g",
        spawnedAt: Date.now(),
        lastUsedAt: Date.now(),
      };
    });

    await expect(acquired).rejects.toMatchObject({ code: ErrorCode.MCP_CONNECT_FAILED });

    // The credential-bearing child is gone, not parked in a registry that no
    // seal, terminate or crash path will ever walk again.
    expect(killSync).toHaveBeenCalled();
    expect(close).toHaveBeenCalled();
    expect(dispose).toHaveBeenCalled();
    expect(reg.get("secret-1")).toBeUndefined();
  });

  it("control: an ordinary connect is published and reachable", async () => {
    registry = new McpConnectionRegistry(null);
    const reg = registry;
    const killSync = vi.fn();

    const entry = await reg.acquire("secret-1", () =>
      Promise.resolve({
        secretId: "secret-1",
        serverName: "ok-mcp",
        transportKind: "stdio" as const,
        client: { close: vi.fn().mockResolvedValue(undefined) } as never,
        stdioTransport: { killSync } as never,
        state: "connecting" as const,
        crashed: false,
        credentialFingerprint: "f",
        configFingerprint: "g",
        spawnedAt: Date.now(),
        lastUsedAt: Date.now(),
      }),
    );

    expect(entry.state).toBe("ready");
    expect(reg.get("secret-1")).toBe(entry);
    expect(killSync).not.toHaveBeenCalled();
  });
});

describe("McpInjector — post-spawn failure (M8)", () => {
  it("kills the credential-bearing child when the spawn audit write fails", async () => {
    // Audit is fail-closed (NM3): an unwritable log throws AFTER the child has
    // been spawned with the plaintext credential in its environment, and before
    // the entry reaches the registry — so no seal, terminate or crash path
    // could ever reach that child again.
    const failingLogger = {
      log: vi.fn(() => {
        throw new Error("audit write failed");
      }),
    } as unknown as AuditLogger;

    registry = new McpConnectionRegistry(null);
    const injector = new McpInjector(failingLogger, registry);

    const dir = mkdtempSync(join(tmpdir(), "harpoc-mcp-orphan-"));
    const pidFile = join(dir, "pid");
    try {
      await expect(
        injector.executeWithSecret(
          action("echo"),
          new Uint8Array(Buffer.from(SECRET, "utf8")),
          POLICY,
          { ...CONFIG, args: ["-e", pidReportingServer(pidFile)] },
          "secret-orphan",
        ),
      ).rejects.toThrow();

      expect(registry.get("secret-orphan")).toBeUndefined();

      const pid = Number(readFileSync(pidFile, "utf8"));
      expect(pid).toBeGreaterThan(0);

      // Signal 0 probes liveness without delivering anything: the child must
      // be gone rather than left running with the plaintext in its env.
      await waitFor(() => !isAlive(pid));
      expect(isAlive(pid)).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 20_000);

  it("control: a healthy connect leaves the child running and registered", async () => {
    registry = new McpConnectionRegistry(null);
    const injector = new McpInjector(null, registry);

    const dir = mkdtempSync(join(tmpdir(), "harpoc-mcp-ok-"));
    const pidFile = join(dir, "pid");
    try {
      await injector.executeWithSecret(
        action("echo"),
        new Uint8Array(Buffer.from(SECRET, "utf8")),
        POLICY,
        { ...CONFIG, args: ["-e", pidReportingServer(pidFile)] },
        "secret-ok",
      );

      expect(registry.get("secret-ok")).toBeDefined();
      expect(isAlive(Number(readFileSync(pidFile, "utf8")))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 20_000);
});
