import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { InjectionPolicy, McpAction, McpServerConfig } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import {
  MONITOR_WRAPPER,
  NODE,
  POLICY,
  SECRET,
  STDIO_CONFIG,
  TEST_SERVER,
  mcpAction,
  monitorWrap,
  payloadPidOf,
  secretBytes,
  spawnRowOf,
} from "./__fixtures__/mcp-downstream.js";
import type { LoggedRow } from "./__fixtures__/mcp-downstream.js";
import { requireIsolation } from "./isolation.js";
import { McpInjector } from "./mcp-injector.js";
import { McpConnectionRegistry } from "./mcp-registry.js";
import { wrapInJob } from "./win32-job-wrapper.js";

vi.mock("./isolation.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./isolation.js")>();
  return { ...actual, requireIsolation: vi.fn(actual.requireIsolation) };
});

vi.mock("./win32-job-wrapper.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./win32-job-wrapper.js")>();
  return { ...actual, wrapInJob: vi.fn(actual.wrapInJob) };
});

const composerMock = vi.mocked(requireIsolation);
const actualIsolation = await vi.importActual<typeof import("./isolation.js")>("./isolation.js");
const jobMock = vi.mocked(wrapInJob);
const actualJob =
  await vi.importActual<typeof import("./win32-job-wrapper.js")>("./win32-job-wrapper.js");

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

describe("McpInjector — the stdio child spawns inside the job wrapper (2026-09-10)", () => {
  /**
   * A node-scripted stand-in for `harpoc-job.exe`: it keeps the wrapper's argv
   * shape (`--keep|--strict <payload> <args...>`), stays as a monitor and
   * returns the payload's exit status, so the wrapped spawn runs end to end on
   * every platform. node's own `--` separator has to precede the flag — without
   * it node claims it as its own (`bad option: --keep`, exit 9) — and node
   * strips the separator, so the stand-in still reads `[flag, command,
   * ...args]` out of `process.argv.slice(1)`.
   */
  const JOB_MONITOR = `
const [flag, command, ...args] = process.argv.slice(1);
const child = require("node:child_process").spawn(command, args, { stdio: "inherit" });
child.on("exit", (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
`;
  beforeEach(() => {
    jobMock.mockReset();
    jobMock.mockImplementation((command, args, mode) =>
      Promise.resolve({
        command: NODE,
        args: [
          "-e",
          JOB_MONITOR,
          "--",
          mode === "strict" ? "--strict" : "--keep",
          command,
          ...args,
        ],
        mechanism: "job" as const,
        mode,
      }),
    );
  });
  afterEach(async () => {
    await registry.closeAll("session_end");
    freshInjector();
    jobMock.mockReset();
    jobMock.mockImplementation(actualJob.wrapInJob);
    composerMock.mockImplementation(actualIsolation.requireIsolation);
  });

  it("wraps the launch after isolation, spawns the WRAPPER, and records tree_kill on mcp.spawn", async () => {
    const log = vi.fn();
    const auditedInjector = new McpInjector({ log } as unknown as AuditLogger, registry);
    const pidResult = await auditedInjector.executeWithSecret(
      mcpAction("pid"),
      secretBytes(),
      POLICY,
      STDIO_CONFIG,
      "secret-1",
    );
    expect(jobMock).toHaveBeenCalledTimes(1);
    expect(jobMock.mock.calls[0]?.[0]).toBe(NODE);
    expect(jobMock.mock.calls[0]?.[1]).toEqual(["-e", TEST_SERVER]);
    const spawnRow = spawnRowOf(log);
    expect(spawnRow?.detail).toMatchObject({ command: NODE, transport: "stdio", tree_kill: "job" });
    expect(typeof spawnRow?.detail.pid).toBe("number");
    expect(payloadPidOf(pidResult)).not.toBe(spawnRow?.detail.pid);
  });

  it("wraps around the isolation wrapper when a dimension is demanded (the job is the outermost)", async () => {
    composerMock.mockImplementation((command, args, dims) => monitorWrap(command, args, dims));
    await run(mcpAction("echo"), { policy: { ...POLICY, network_isolation: true } });
    const [command, args] = jobMock.mock.calls[0] as Parameters<typeof wrapInJob>;
    expect(command).toBe(NODE);
    expect(args.slice(0, 2)).toEqual(["-e", MONITOR_WRAPPER]);
  });

  it("records no tree_kill when the wrapper is unavailable off win32", async () => {
    jobMock.mockResolvedValue({ mechanism: null, reason: "test: unavailable" });
    const log = vi.fn();
    const auditedInjector = new McpInjector({ log } as unknown as AuditLogger, registry);
    await auditedInjector.executeWithSecret(
      mcpAction("echo"),
      secretBytes(),
      POLICY,
      STDIO_CONFIG,
      "secret-1",
    );
    const spawnRow = spawnRowOf(log);
    if (process.platform === "win32")
      expect(spawnRow?.detail).toMatchObject({ tree_kill: "taskkill" });
    else expect(spawnRow !== undefined && "tree_kill" in spawnRow.detail).toBe(false);
  });

  it("asks for strict mode when the policy demands it and marks mcp.spawn (D2, 2026-09-10)", async () => {
    const log = vi.fn();
    const auditedInjector = new McpInjector({ log } as unknown as AuditLogger, registry);
    await auditedInjector.executeWithSecret(
      mcpAction("echo"),
      secretBytes(),
      { ...POLICY, strict_tree_exit: true },
      STDIO_CONFIG,
      "secret-1",
    );
    expect(jobMock.mock.calls[0]?.[2]).toBe("strict");
    expect(spawnRowOf(log)?.detail).toMatchObject({ tree_kill: "job", strict_tree_exit: true });
  });

  it("a strict demand newly set on a live keep-mode child terminates and respawns it (the posture backstop)", async () => {
    const log = vi.fn();
    // The mcp.terminate row is the REGISTRY's, written through the registry's
    // own logger — the module-level one is constructed with none, so this case
    // runs against a registry sharing the injector's logger and tears its own
    // child down (the file-level afterEach only walks `registry`).
    const auditedRegistry = new McpConnectionRegistry({ log } as unknown as AuditLogger);
    const auditedInjector = new McpInjector({ log } as unknown as AuditLogger, auditedRegistry);
    try {
      await auditedInjector.executeWithSecret(
        mcpAction("echo"),
        secretBytes(),
        POLICY,
        STDIO_CONFIG,
        "secret-1",
      );
      await auditedInjector.executeWithSecret(
        mcpAction("echo"),
        secretBytes(),
        { ...POLICY, strict_tree_exit: true },
        STDIO_CONFIG,
        "secret-1",
      );
      const rows = log.mock.calls.map(
        (c) => c[0] as { eventType: string; detail: Record<string, unknown> },
      );
      expect(rows.filter((r) => r.eventType === "mcp.spawn")).toHaveLength(2);
      expect(rows.find((r) => r.eventType === "mcp.terminate")?.detail).toMatchObject({
        reason: "strict_tree_exit_enabled",
      });
      // Loosening leaves the child alone.
      await auditedInjector.executeWithSecret(
        mcpAction("echo"),
        secretBytes(),
        POLICY,
        STDIO_CONFIG,
        "secret-1",
      );
      expect(
        log.mock.calls.filter((c) => (c[0] as { eventType: string }).eventType === "mcp.spawn"),
      ).toHaveLength(2);
    } finally {
      await auditedRegistry.closeAll("test_cleanup");
    }
  });

  /**
   * A downstream server that leaves a detached grandchild holding its inherited
   * pipes (C1, 2026-09-10). The vault's close() settles on 'exit', so the
   * child's own 'close' — and the registry hook riding it — lands seconds
   * later, long after the terminate that ended it and after its successor was
   * published.
   */
  const GRANDCHILD_SERVER =
    `
const g = require("node:child_process").spawn(process.execPath, ["-e", "setTimeout(() => {}, 60000)"], { stdio: "inherit", detached: true, windowsHide: true });
g.unref();
process.stderr.write("gpid=" + String(g.pid) + "\\n");
` + TEST_SERVER;
  const GRANDCHILD_CONFIG: McpServerConfig = { ...STDIO_CONFIG, args: ["-e", GRANDCHILD_SERVER] };

  async function grandchildPidOf(transport: { stderrTail: { toString: () => string } }) {
    const deadline = Date.now() + 10_000;
    for (;;) {
      const m = /gpid=(\d+)/.exec(transport.stderrTail.toString());
      if (m) return Number(m[1]);
      if (Date.now() >= deadline) return 0;
      await new Promise((r) => setTimeout(r, 50));
    }
  }

  function killGrandchildren(tail: string): void {
    for (const m of tail.matchAll(/gpid=(\d+)/g)) {
      try {
        process.kill(Number(m[1]), "SIGKILL");
      } catch {
        // Gone.
      }
    }
  }

  it("a late close from a terminated child never evicts its successor's registry slot (C1)", async () => {
    const log = vi.fn();
    const auditedInjector = new McpInjector({ log } as unknown as AuditLogger, registry);
    const tails: (() => string)[] = [];
    try {
      await auditedInjector.executeWithSecret(
        mcpAction("echo"),
        secretBytes(),
        POLICY,
        GRANDCHILD_CONFIG,
        "secret-1",
      );
      const first = registry.get("secret-1");
      const firstTransport = first?.stdioTransport;
      expect(firstTransport).toBeDefined();
      const transport = firstTransport as NonNullable<typeof firstTransport>;
      tails.push(() => transport.stderrTail.toString());
      const grandchild = await grandchildPidOf(transport);
      expect(grandchild).toBeGreaterThan(0);

      // The strict demand terminates the keep-mode child and respawns it; the
      // old child's 'close' stays withheld by its grandchild.
      await auditedInjector.executeWithSecret(
        mcpAction("echo"),
        secretBytes(),
        { ...POLICY, strict_tree_exit: true },
        GRANDCHILD_CONFIG,
        "secret-1",
      );
      const second = registry.get("secret-1");
      expect(second).toBeDefined();
      expect(second).not.toBe(first);
      const secondTransport = second?.stdioTransport;
      if (secondTransport) tails.push(() => secondTransport.stderrTail.toString());
      expect(transport.exitInfo).toBeNull();

      // Release the old pipes: the old child's 'close' lands now, seconds after
      // the terminate that ended it, and drives the registry's close hook.
      process.kill(grandchild, "SIGKILL");
      const deadline = Date.now() + 15_000;
      while (transport.exitInfo === null && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 50));
      }
      expect(transport.exitInfo).not.toBeNull();

      // The successor must still be reachable: same policy, so no backstop.
      await auditedInjector.executeWithSecret(
        mcpAction("echo"),
        secretBytes(),
        { ...POLICY, strict_tree_exit: true },
        GRANDCHILD_CONFIG,
        "secret-1",
      );
      expect(
        log.mock.calls.filter((c) => (c[0] as { eventType: string }).eventType === "mcp.spawn"),
      ).toHaveLength(2);
      expect(registry.get("secret-1")).toBe(second);
    } finally {
      // A red run leaves nothing standing (2026-09-07): every grandchild any
      // spawn of this case produced is ended here.
      await registry.closeAll("test_cleanup");
      for (const tail of tails) killGrandchildren(tail());
    }
  }, 60_000);

  it.runIf(process.platform === "win32")(
    "win32: a strict secret with no wrapper is refused before the spawn, audited, naming the reason",
    async () => {
      jobMock.mockResolvedValue({ mechanism: null, reason: "test: no wrapper on this host" });
      const log = vi.fn();
      const auditedInjector = new McpInjector({ log } as unknown as AuditLogger, registry);
      await expect(
        auditedInjector.executeWithSecret(
          mcpAction("echo"),
          secretBytes(),
          { ...POLICY, strict_tree_exit: true },
          STDIO_CONFIG,
          "secret-1",
        ),
      ).rejects.toMatchObject({
        code: ErrorCode.STRICT_TREE_EXIT_UNAVAILABLE,
        message: expect.stringContaining("test: no wrapper on this host"),
      });
      expect(spawnRowOf(log)).toBeUndefined();
      const failure = log.mock.calls
        .map((c) => c[0] as { success: boolean; detail: Record<string, unknown> })
        .find((r) => !r.success);
      expect(failure?.detail).toMatchObject({
        error: ErrorCode.STRICT_TREE_EXIT_UNAVAILABLE,
        strict_tree_exit: true,
      });
    },
  );

  it.runIf(process.platform !== "win32")(
    "POSIX: a strict secret runs without a wrapper, marked strict on mcp.spawn, no tree_kill",
    async () => {
      jobMock.mockResolvedValue({ mechanism: null, reason: "unsupported platform: linux" });
      const log = vi.fn();
      const auditedInjector = new McpInjector({ log } as unknown as AuditLogger, registry);
      await auditedInjector.executeWithSecret(
        mcpAction("echo"),
        secretBytes(),
        { ...POLICY, strict_tree_exit: true },
        STDIO_CONFIG,
        "secret-1",
      );
      const spawnRow = spawnRowOf(log);
      expect(spawnRow?.detail).toMatchObject({ strict_tree_exit: true });
      expect(spawnRow !== undefined && "tree_kill" in spawnRow.detail).toBe(false);
    },
  );

  it.runIf(process.platform === "win32")(
    "a payload the wrapper cannot start is MCP_CONNECT_FAILED 'spawn failed', never a crash (note 1)",
    async () => {
      jobMock.mockImplementation(() =>
        Promise.resolve({
          command: NODE,
          args: [
            "-e",
            "process.stderr.write('harpoc-job: CreateProcess failed: 3'); process.exit(9009)",
          ],
          mechanism: "job" as const,
          mode: "keep" as const,
        }),
      );
      const log = vi.fn();
      const auditedInjector = new McpInjector({ log } as unknown as AuditLogger, registry);
      const err = await auditedInjector
        .executeWithSecret(mcpAction("echo"), secretBytes(), POLICY, STDIO_CONFIG, "secret-1")
        .then(
          () => undefined,
          (e: unknown) => e as { code: string; message: string },
        );
      expect(err?.code).toBe(ErrorCode.MCP_CONNECT_FAILED);
      expect(err?.message).toContain("spawn failed: harpoc-job: CreateProcess failed: 3");
      expect(
        log.mock.calls.map((c) => (c[0] as { detail: Record<string, unknown> }).detail.error),
      ).not.toContain(ErrorCode.MCP_SERVER_CRASHED);
    },
  );

  /**
   * I1 (2026-09-10): the marker line is downstream stderr and D4 accepts a
   * payload faking the reserved pair, so the payload CHOOSES it — and the
   * thrown message is served to the model as tool-result text and to a REST
   * client as an error body, a surface no result-shaped redaction sees. The
   * line must therefore be bounded where it is built and given the crash
   * row's own treatment (exact-value redaction, then the guard's patterns).
   */
  it.runIf(process.platform === "win32")(
    "the wrapper-failure line in the message is bounded, exact-redacted and pattern-guarded (I1)",
    async () => {
      const markerHead = "harpoc-job: CreateProcess failed";
      const fakedLine =
        markerHead +
        "; token: " +
        "A".repeat(24) +
        "; env=" +
        SECRET +
        "; " +
        "P".repeat(2_000) +
        "PAST-THE-BOUND";
      jobMock.mockImplementation(() =>
        Promise.resolve({
          command: NODE,
          args: [
            "-e",
            "process.stderr.write(" + JSON.stringify(fakedLine) + "); process.exit(9009)",
          ],
          mechanism: "job" as const,
          mode: "keep" as const,
        }),
      );
      const err = await injector
        .executeWithSecret(mcpAction("echo"), secretBytes(), POLICY, STDIO_CONFIG, "secret-1")
        .then(
          () => undefined,
          (e: unknown) => e as { code: string; message: string },
        );
      const prefix = "Failed to connect to MCP server 'test-mcp': spawn failed: ";
      expect(err?.code).toBe(ErrorCode.MCP_CONNECT_FAILED);
      expect(err?.message.startsWith(prefix + markerHead)).toBe(true);
      // Bounded at its one construction site: a line's worth, never 64 KiB.
      expect((err?.message.length ?? 0) - prefix.length).toBeLessThanOrEqual(512);
      expect(err?.message).not.toContain("PAST-THE-BOUND");
      // Exact-value redaction, then the guard's pattern pass — the crash row's
      // treatment, not a third variant of it.
      expect(err?.message).not.toContain(SECRET);
      expect(err?.message).toContain("token:[REDACTED]");
    },
  );

  /**
   * A downstream server that completes the SDK handshake and only then fakes
   * the wrapper's own failure (I2, 2026-09-10) — derived from TEST_SERVER's
   * `initialize` arm. `establish` therefore succeeds and the entry is
   * published ready, so the branch under test is the IN-FLIGHT mapping
   * (`mapCallError`), not the connect-time one, and the registry's crash row
   * is written from the same exit. The faked line carries the credential the
   * vault injected into this very child (ledger L128) and a token the guard's
   * patterns recognize.
   */
  const WRAPPER_FAILURE_ON_CALL_SERVER = `
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") {
    console.log(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: {
      protocolVersion: m.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "harpoc-test-downstream", version: "1.0.0" },
    }}));
  } else if (m.method === "tools/call") {
    process.stderr.write("harpoc-job: assign to job failed: 5; token: AAAAAAAAAAAAAAAAAAAAAAAA; env=" + process.env.DOWNSTREAM_TOKEN);
    process.exit(9009);
  }
});
`;
  const WRAPPER_FAILURE_CONFIG: McpServerConfig = {
    ...STDIO_CONFIG,
    args: ["-e", WRAPPER_FAILURE_ON_CALL_SERVER],
  };

  it.runIf(process.platform === "win32")(
    "an in-flight wrapper failure is MCP_CONNECT_FAILED 'spawn failed', and mcp.crash carries a null exit with spawn_failed (I2)",
    async () => {
      const log = vi.fn();
      // The crash row is the REGISTRY's, written through the registry's own
      // logger — the module-level one is constructed with none.
      const auditedRegistry = new McpConnectionRegistry({ log } as unknown as AuditLogger);
      const auditedInjector = new McpInjector({ log } as unknown as AuditLogger, auditedRegistry);
      try {
        const err = await auditedInjector
          .executeWithSecret(
            mcpAction("echo"),
            secretBytes(),
            POLICY,
            WRAPPER_FAILURE_CONFIG,
            "secret-1",
          )
          .then(
            () => undefined,
            (e: unknown) => e as { code: string; message: string },
          );
        expect(err?.code).toBe(ErrorCode.MCP_CONNECT_FAILED);
        expect(err?.message).toContain("spawn failed: harpoc-job: assign to job failed: 5");
        expect(err?.message).not.toContain(SECRET);
        expect(err?.message).toContain("token:[REDACTED]");

        const crash = log.mock.calls
          .map((c) => c[0] as LoggedRow)
          .find((r) => r.eventType === "mcp.crash");
        expect(crash?.success).toBe(false);
        expect(crash?.detail).toMatchObject({
          server: "test-mcp",
          transport: "stdio",
          exit_code: null,
          signal: null,
          spawn_failed: true,
        });
        expect(JSON.stringify(crash?.detail)).not.toContain(SECRET);
        // No auto-respawn: the crashed entry is gone.
        expect(auditedRegistry.get("secret-1")).toBeUndefined();
      } finally {
        await auditedRegistry.closeAll("test_cleanup");
      }
    },
  );
});
