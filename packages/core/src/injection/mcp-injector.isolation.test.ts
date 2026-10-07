import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { InjectionPolicy, McpAction, McpServerConfig } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import {
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
import { forceFsIsolationUnavailableForTests } from "./fs-isolation.js";
import { requireIsolation } from "./isolation.js";
import type { IsolationDimensions } from "./isolation.js";
import { McpInjector } from "./mcp-injector.js";
import { McpConnectionRegistry } from "./mcp-registry.js";
import { forceNetworkIsolationUnavailableForTests } from "./network-isolation.js";

vi.mock("./isolation.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./isolation.js")>();
  return { ...actual, requireIsolation: vi.fn(actual.requireIsolation) };
});

const composerMock = vi.mocked(requireIsolation);
const actualIsolation = await vi.importActual<typeof import("./isolation.js")>("./isolation.js");

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

describe("McpInjector — isolation: refused on a host that cannot deliver (§4.5.3 layer 4)", () => {
  beforeEach(() => {
    composerMock.mockClear();
    forceNetworkIsolationUnavailableForTests("forced: no network tier");
    forceFsIsolationUnavailableForTests("forced: no filesystem tier");
  });
  afterEach(async () => {
    forceNetworkIsolationUnavailableForTests(null);
    forceFsIsolationUnavailableForTests(null);
    await registry.closeAll("session_end");
    freshInjector();
  });

  it("refuses a stdio downstream fail-closed before any acquire", async () => {
    const acquireSpy = vi.spyOn(registry, "acquire");
    await expect(
      run(mcpAction("echo"), { policy: { ...POLICY, network_isolation: true } }),
    ).rejects.toMatchObject({ code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE });
    expect(acquireSpy).not.toHaveBeenCalled();
  });

  it("terminates a live un-isolated child before refusing (policy tightened elsewhere)", async () => {
    await run(mcpAction("echo"));
    expect(registry.get("secret-1")).toBeDefined();
    await expect(
      run(mcpAction("echo"), { policy: { ...POLICY, network_isolation: true } }),
    ).rejects.toMatchObject({ code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE });
    expect(registry.get("secret-1")).toBeUndefined();
  });

  it("leaves the live child alone when the policy does not demand isolation", async () => {
    await run(mcpAction("echo"));
    const entry = registry.get("secret-1");
    expect(entry).toBeDefined();
    await run(mcpAction("echo"));
    expect(registry.get("secret-1")).toBe(entry);
  });

  it("audits the network refusal with the error code and the flag alone", async () => {
    const log = vi.fn();
    const auditedInjector = new McpInjector({ log } as unknown as AuditLogger, registry);
    await expect(
      auditedInjector.executeWithSecret(
        mcpAction("echo"),
        secretBytes(),
        { ...POLICY, network_isolation: true },
        STDIO_CONFIG,
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE });
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        detail: expect.objectContaining({
          error: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE,
          network_isolation: true,
        }),
      }),
    );
    const row = log.mock.calls
      .map((c) => c[0] as LoggedRow)
      .find((r) => r.detail.error === ErrorCode.NETWORK_ISOLATION_UNAVAILABLE);
    expect(row !== undefined && "fs_isolation" in row.detail).toBe(false);
  });

  it("terminates the live child, refuses and audits the filesystem refusal", async () => {
    await run(mcpAction("echo"));
    expect(registry.get("secret-1")).toBeDefined();
    const terminateSpy = vi.spyOn(registry, "terminate");
    const log = vi.fn();
    const auditedInjector = new McpInjector({ log } as unknown as AuditLogger, registry);
    await expect(
      auditedInjector.executeWithSecret(
        mcpAction("echo"),
        secretBytes(),
        { ...POLICY, fs_isolation: true },
        STDIO_CONFIG,
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.FS_ISOLATION_UNAVAILABLE });
    expect(terminateSpy).toHaveBeenCalledWith("secret-1", "fs_isolation_enabled", undefined);
    expect(registry.get("secret-1")).toBeUndefined();
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        detail: expect.objectContaining({
          error: ErrorCode.FS_ISOLATION_UNAVAILABLE,
          fs_isolation: true,
        }),
      }),
    );
  });

  it("refuses with the filesystem code when both flags are demanded (the composer's order, R-f), one terminate under the network reason, both flags on the row", async () => {
    const terminateSpy = vi.spyOn(registry, "terminate");
    const log = vi.fn();
    const auditedInjector = new McpInjector({ log } as unknown as AuditLogger, registry);
    await expect(
      auditedInjector.executeWithSecret(
        mcpAction("echo"),
        secretBytes(),
        { ...POLICY, network_isolation: true, fs_isolation: true },
        STDIO_CONFIG,
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.FS_ISOLATION_UNAVAILABLE });
    expect(terminateSpy).toHaveBeenCalledTimes(1);
    expect(terminateSpy).toHaveBeenCalledWith("secret-1", "network_isolation_enabled", undefined);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        detail: expect.objectContaining({
          error: ErrorCode.FS_ISOLATION_UNAVAILABLE,
          network_isolation: true,
          fs_isolation: true,
        }),
      }),
    );
  });

  it("does not gate an HTTP downstream on either flag (request-mediated, no child)", async () => {
    const terminateSpy = vi.spyOn(registry, "terminate");
    const err = await run(mcpAction("echo"), {
      config: {
        server_name: "test-mcp",
        transport: "http",
        protocol: "2025-11-25",
        url: "http://127.0.0.1:9/mcp",
      },
      policy: {
        ...POLICY,
        network_isolation: true,
        fs_isolation: true,
        url_allowlist: ["http://127.0.0.1:9/*"],
      },
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VaultError);
    expect((err as VaultError).code).not.toBe(ErrorCode.NETWORK_ISOLATION_UNAVAILABLE);
    expect((err as VaultError).code).not.toBe(ErrorCode.FS_ISOLATION_UNAVAILABLE);
    expect(terminateSpy).not.toHaveBeenCalled();
    expect(composerMock).not.toHaveBeenCalled();
  });
});

describe("McpInjector — isolation: the stdio child spawns wrapped (D51)", () => {
  beforeEach(() => {
    composerMock.mockClear();
    composerMock.mockImplementation((command, args, dims) => monitorWrap(command, args, dims));
  });
  afterEach(async () => {
    await registry.closeAll("session_end");
    freshInjector();
    composerMock.mockImplementation(actualIsolation.requireIsolation);
  });

  it("sends the resolved command and the configured args through the composer, spawns the WRAPPER, records the mechanism on mcp.spawn and the posture on the entry", async () => {
    const log = vi.fn();
    const auditedInjector = new McpInjector({ log } as unknown as AuditLogger, registry);
    const pidResult = await auditedInjector.executeWithSecret(
      mcpAction("pid"),
      secretBytes(),
      { ...POLICY, network_isolation: true },
      STDIO_CONFIG,
      "secret-1",
    );
    expect(pidResult.type).toBe("mcp");

    expect(composerMock).toHaveBeenCalledTimes(1);
    const [command, args, dims] = composerMock.mock.calls[0] as [
      string,
      readonly string[],
      IsolationDimensions,
    ];
    expect(command.length).toBeGreaterThan(0);
    expect(args).toEqual(["-e", TEST_SERVER]);
    expect(dims).toEqual({ network: true, fs: false });

    const spawnRow = spawnRowOf(log);
    expect(spawnRow?.detail).toMatchObject({
      command: NODE,
      transport: "stdio",
      isolation_mechanism: "unshare",
    });
    expect(spawnRow !== undefined && "fs_isolation_mechanism" in spawnRow.detail).toBe(false);
    // The vault holds the wrapper's pid; the payload reports its own — under
    // a monitor-style wrapper they differ. Spawning the bare command instead
    // of the wrapper would make them equal (the guard-flip for this task).
    expect(typeof spawnRow?.detail.pid).toBe("number");
    expect(payloadPidOf(pidResult)).toBeGreaterThan(0);
    expect(payloadPidOf(pidResult)).not.toBe(spawnRow?.detail.pid);
    expect(registry.get("secret-1")?.isolation).toEqual({ network: true, fs: false });
  });

  it("records both mechanisms when both dimensions are demanded", async () => {
    const log = vi.fn();
    const auditedInjector = new McpInjector({ log } as unknown as AuditLogger, registry);
    await auditedInjector.executeWithSecret(
      mcpAction("echo"),
      secretBytes(),
      { ...POLICY, network_isolation: true, fs_isolation: true },
      STDIO_CONFIG,
      "secret-1",
    );
    expect(spawnRowOf(log)?.detail).toMatchObject({
      isolation_mechanism: "unshare",
      fs_isolation_mechanism: "landlock",
    });
    expect(registry.get("secret-1")?.isolation).toEqual({ network: true, fs: true });
  });

  it("never consults the composer, and records the bare posture, when neither flag is set", async () => {
    await run(mcpAction("echo"));
    expect(composerMock).not.toHaveBeenCalled();
    expect(registry.get("secret-1")?.isolation).toEqual({ network: false, fs: false });
  });

  it("terminates a live un-isolated child under the network reason and respawns it wrapped when the policy tightens (the cross-process backstop)", async () => {
    const before = await run(mcpAction("pid"));
    const entryBefore = registry.get("secret-1");
    expect(entryBefore?.isolation).toEqual({ network: false, fs: false });
    const terminateSpy = vi.spyOn(registry, "terminate");

    const after = await run(mcpAction("pid"), { policy: { ...POLICY, network_isolation: true } });

    expect(terminateSpy).toHaveBeenCalledTimes(1);
    expect(terminateSpy).toHaveBeenCalledWith("secret-1", "network_isolation_enabled", undefined);
    expect(payloadPidOf(after)).not.toBe(payloadPidOf(before));
    expect(registry.get("secret-1")).not.toBe(entryBefore);
    expect(registry.get("secret-1")?.isolation).toEqual({ network: true, fs: false });
  });

  it("uses the filesystem reason when only that dimension is newly demanded", async () => {
    await run(mcpAction("echo"), { policy: { ...POLICY, network_isolation: true } });
    const terminateSpy = vi.spyOn(registry, "terminate");
    await run(mcpAction("echo"), {
      policy: { ...POLICY, network_isolation: true, fs_isolation: true },
    });
    expect(terminateSpy).toHaveBeenCalledTimes(1);
    expect(terminateSpy).toHaveBeenCalledWith("secret-1", "fs_isolation_enabled", undefined);
    expect(registry.get("secret-1")?.isolation).toEqual({ network: true, fs: true });
  });

  it("uses the filesystem reason when the filesystem dimension and strict tree exit are newly demanded together (fs outranks strict)", async () => {
    await run(mcpAction("echo"));
    const terminateSpy = vi.spyOn(registry, "terminate");
    await run(mcpAction("echo"), {
      policy: { ...POLICY, fs_isolation: true, strict_tree_exit: true },
    });
    expect(terminateSpy).toHaveBeenCalledTimes(1);
    expect(terminateSpy).toHaveBeenCalledWith("secret-1", "fs_isolation_enabled", undefined);
    expect(registry.get("secret-1")?.isolation).toEqual({ network: false, fs: true });
    expect(registry.get("secret-1")?.strictTreeExit).toBe(true);
  });

  it("leaves a wrapped child alone when the policy loosens or is re-asserted", async () => {
    await run(mcpAction("echo"), { policy: { ...POLICY, fs_isolation: true } });
    const entry = registry.get("secret-1");
    const terminateSpy = vi.spyOn(registry, "terminate");
    await run(mcpAction("echo"));
    expect(registry.get("secret-1")).toBe(entry);
    await run(mcpAction("echo"), { policy: { ...POLICY, fs_isolation: true } });
    expect(registry.get("secret-1")).toBe(entry);
    expect(terminateSpy).not.toHaveBeenCalled();
  });

  it("recomputes the wrap on every call, warm connection included (complete mediation)", async () => {
    await run(mcpAction("echo"), { policy: { ...POLICY, network_isolation: true } });
    const entry = registry.get("secret-1");
    await run(mcpAction("echo"), { policy: { ...POLICY, network_isolation: true } });
    expect(composerMock).toHaveBeenCalledTimes(2);
    expect(registry.get("secret-1")).toBe(entry);
  });

  it("still redacts the credential echoed back through the wrapper", async () => {
    const leak = await run(mcpAction("leak-env"), {
      policy: { ...POLICY, network_isolation: true },
    });
    expect(JSON.stringify(leak)).not.toContain(SECRET);
  });
});
