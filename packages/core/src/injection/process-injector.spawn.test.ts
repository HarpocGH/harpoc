import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ProcessAction } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { ProcessInjector } from "./process-injector.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";

vi.mock("./spawn-captured.js", () => ({ spawnCaptured: vi.fn() }));

/**
 * The process context's isolation wiring at the spawn seam. The Git and SSH
 * contexts pin the same hand-off in their own `*.spawn.test.ts` files; the
 * process context had no mocked-seam suite because its network-isolation cases
 * run against the real seam (process-injector.test.ts). A mocked seam is the
 * only portable way to observe the option the injector passes and the mechanism
 * it audits back — the real wrapper exists on neither Windows nor a
 * Landlock-less host.
 */

const NODE = process.execPath;
const SECRET = "sk-supersecret-abcdef123456";

const OK_RESULT: SpawnCapturedResult = {
  exit_code: 0,
  stdout: "",
  stderr: "",
  timed_out: false,
  truncated: false,
  signal: null,
  spawn_failed: false,
};

const ACTION: ProcessAction = {
  type: "process",
  command: NODE,
  args: ["-e", "process.exit(0)"],
  env_var: "SECRET",
};

type SpawnOpts = { networkIsolation?: boolean; fsIsolation?: boolean };

describe("ProcessInjector filesystem isolation (§4.5.3 layer 4)", () => {
  const spawnMock = vi.mocked(spawnCaptured);

  beforeEach(() => {
    spawnMock.mockReset();
  });

  it("passes the policy flag into the spawn seam and audits mechanism + state", async () => {
    const log = vi.fn();
    const audited = new ProcessInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue({ ...OK_RESULT, fs_isolation_mechanism: "landlock" });
    await audited.executeWithSecret(
      ACTION,
      new Uint8Array(Buffer.from(SECRET, "utf8")),
      { command_allowlist: [NODE], env_allowlist: [], fs_isolation: true },
      "secret-1",
    );
    const [, , opts] = spawnMock.mock.calls[0] as [string, string[], SpawnOpts];
    expect(opts.fsIsolation).toBe(true);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        detail: expect.objectContaining({
          context: "process",
          fs_isolation: true,
          fs_isolation_mechanism: "landlock",
        }),
      }),
    );
  });

  it("audits and rethrows the fail-closed refusal from the seam", async () => {
    const log = vi.fn();
    const audited = new ProcessInjector({ log } as unknown as AuditLogger);
    spawnMock.mockRejectedValue(VaultError.fsIsolationUnavailable("mocked"));
    await expect(
      audited.executeWithSecret(
        ACTION,
        new Uint8Array(Buffer.from(SECRET, "utf8")),
        { command_allowlist: [NODE], env_allowlist: [], fs_isolation: true },
        "secret-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.FS_ISOLATION_UNAVAILABLE });
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

  it("defaults to an un-isolated spawn and audits fs_isolation: false", async () => {
    const log = vi.fn();
    const audited = new ProcessInjector({ log } as unknown as AuditLogger);
    spawnMock.mockResolvedValue(OK_RESULT);
    await audited.executeWithSecret(
      ACTION,
      new Uint8Array(Buffer.from(SECRET, "utf8")),
      { command_allowlist: [NODE], env_allowlist: [] },
      "secret-1",
    );
    const [, , opts] = spawnMock.mock.calls[0] as [string, string[], SpawnOpts];
    expect(opts.fsIsolation).toBe(false);
    expect(opts.networkIsolation).toBe(false);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        detail: expect.objectContaining({ fs_isolation: false }),
      }),
    );
    // No mechanism key when no wrapper ran.
    const row = log.mock.calls[0]?.[0] as { detail: Record<string, unknown> };
    expect("fs_isolation_mechanism" in row.detail).toBe(false);
  });
});
