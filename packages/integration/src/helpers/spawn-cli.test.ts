import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { VaultEngine } from "@harpoc/core";
import { SESSION_FILE_NAME, VAULT_DB_NAME } from "@harpoc/shared";
import {
  freePort,
  runCli,
  startCliServer,
  startCliServerOnFreePort,
  type CliServer,
} from "./spawn-cli.js";

const PASSWORD = "spawn-cli-helper-pw-1";

describe("startCliServer", () => {
  let vaultDir: string;

  beforeAll(async () => {
    vaultDir = mkdtempSync(join(tmpdir(), "harpoc-spawn-cli-"));
    const engine = new VaultEngine({
      dbPath: join(vaultDir, VAULT_DB_NAME),
      sessionPath: join(vaultDir, SESSION_FILE_NAME),
    });
    await engine.initVault(PASSWORD);
    await engine.destroy();
    const unlock = await runCli(["unlock"], { vaultDir, stdin: `${PASSWORD}\n` });
    expect(unlock.code).toBe(0);
  }, 120_000);

  afterAll(() => {
    rmSync(vaultDir, { recursive: true, force: true });
  });

  it("a spawn failure rejects waitForStderr instead of crashing the worker", async () => {
    const server = startCliServer(["server", "start", "--rest"], { vaultDir: "/nonexistent" });
    server.child.emit("error", new Error("spawn ENOENT"));
    await expect(server.waitForStderr(/never matches/, 500)).rejects.toThrow("spawn ENOENT");
    await server.stop();
  });

  it("retries onto a fresh port when the picked one is already taken", async () => {
    const taken = await freePort();
    const blocker = createServer((socket) => {
      socket.destroy();
    });
    await new Promise<void>((resolve) => blocker.listen(taken, "127.0.0.1", resolve));
    const picks = [taken];
    let started: { server: CliServer; port: number } | undefined;
    try {
      started = await startCliServerOnFreePort(
        (p) => ["server", "start", "--rest", "--port", String(p)],
        { vaultDir, pickPort: async () => picks.shift() ?? (await freePort()) },
      );
      expect(started.port).not.toBe(taken);
      expect((await fetch(`http://127.0.0.1:${String(started.port)}/api/v1/health`)).status).toBe(
        200,
      );
    } finally {
      if (started) await started.server.stop();
      await new Promise<void>((resolve) => blocker.close(() => resolve()));
    }
  }, 120_000);
});
