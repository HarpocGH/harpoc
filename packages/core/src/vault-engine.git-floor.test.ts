import { mkdirSync, mkdtempSync, readdirSync, realpathSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GitAction } from "@harpoc/shared";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { resolveSupportedGit } from "./injection/__fixtures__/supported-git.js";
import { spawnCaptured } from "./injection/spawn-captured.js";
import type { SpawnCapturedResult } from "./injection/spawn-captured.js";
import { VaultEngine } from "./vault-engine.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);
vi.mock("./injection/spawn-captured.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./injection/spawn-captured.js")>();
  return { ...actual, spawnCaptured: vi.fn() };
});

const GIT = resolveSupportedGit();

const REPOSITORY = "https://127.0.0.1:1/harpoc/floor.git";
const CLONE_WITHOUT_DIRECTORY: GitAction = {
  type: "git",
  operation: "clone",
  repository: REPOSITORY,
};

const FAILED_STEP: SpawnCapturedResult = {
  exit_code: 1,
  stdout: "",
  stderr: "",
  timed_out: false,
  truncated: false,
  signal: null,
  spawn_failed: false,
  redacted: false,
};

const spawnMock = vi.mocked(spawnCaptured);
let tempDir: string;
let engine: VaultEngine;

beforeEach(async () => {
  // `.native` like the judgement's realpath: it expands a win32 short name (C:\Users\RUNNER~1 on CI).
  tempDir = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-git-floor-engine-")));
  for (const dir of ["vault", "session", "declared"]) mkdirSync(join(tempDir, dir));
  engine = new VaultEngine({
    dbPath: join(tempDir, "vault", "test.vault.db"),
    sessionPath: join(tempDir, "session", "session.json"),
  });
  await engine.initVault("password");
  spawnMock.mockReset();
  spawnMock.mockResolvedValue(FAILED_STEP);
});

afterEach(async () => {
  spawnMock.mockReset();
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

async function gitSecret(): Promise<string> {
  await engine.createSecret({
    name: "git-floor",
    type: "api_key",
    value: new Uint8Array(Buffer.from("x-access-token:git-floor-value")),
  });
  const handle = "secret://git-floor";
  await engine.setInjectionPolicy(handle, {
    command_allowlist: [GIT as string],
    url_allowlist: ["https://127.0.0.1:1/*"],
  });
  return handle;
}

function clone(destination: string): GitAction {
  return {
    type: "git",
    operation: "clone",
    repository: REPOSITORY,
    working_directory: destination,
  };
}

async function useRows(handle: string): Promise<ReturnType<VaultEngine["queryAudit"]>> {
  const secretId = await engine.resolveSecretId(handle);
  return engine.queryAudit({ secretId, eventType: AuditEventType.SECRET_USE });
}

async function expectRefusedWithOneNewRow(
  handle: string,
  destination: string,
  rowsBefore: number,
): Promise<void> {
  await expectVaultError(
    () => engine.useSecret(handle, clone(destination)),
    ErrorCode.LOCAL_PATH_NOT_ALLOWED,
  );
  const rows = await useRows(handle);
  expect(rows).toHaveLength(rowsBefore + 1);
  const [row] = rows;
  expect(row?.success).toBe(false);
  expect(row?.detail).toEqual({
    context: "git",
    operation: "clone",
    error: ErrorCode.LOCAL_PATH_NOT_ALLOWED,
  });
  expect(JSON.stringify(row).includes(JSON.stringify(tempDir).slice(1, -1))).toBe(false);
  expect(spawnMock).not.toHaveBeenCalled();
}

describe.skipIf(GIT === null)(
  "VaultEngine's git arm: the floor reaches the git context (skipped where no supported git resolves)",
  () => {
    it("a clone into the vault's own directory is refused by the engine", async () => {
      const handle = await gitSecret();
      await expectRefusedWithOneNewRow(handle, join(tempDir, "vault", "clone"), 0);
    });

    it("after declareDaemon a clone into a declared directory is refused", async () => {
      const handle = await gitSecret();
      const declared = join(tempDir, "declared");
      const destination = join(declared, "clone");

      const before = await engine.useSecret(handle, clone(destination));
      expect(before).toMatchObject({ type: "git", exit_code: 1 });
      expect(spawnMock).toHaveBeenCalledTimes(1);
      const [rowBefore] = await useRows(handle);
      expect(rowBefore?.detail?.error).not.toBe(ErrorCode.LOCAL_PATH_NOT_ALLOWED);

      spawnMock.mockClear();
      engine.declareDaemon({ protectedDirs: [declared], protectedFiles: [] });
      await expectRefusedWithOneNewRow(handle, destination, 1);
    });

    // A symbolic link needs a privilege on win32, and only off win32 does the system resolve a
    // `..` behind a link from the link's target.
    it.skipIf(process.platform === "win32")(
      "after declareDaemon a clone spelled through a link into the vault's directory and `..` into a declared directory is refused with one failed row, nothing written",
      async () => {
        const handle = await gitSecret();
        const declared = join(tempDir, "declared");
        mkdirSync(join(tempDir, "agent"));
        const link = join(tempDir, "agent", "link");
        symlinkSync(join(tempDir, "vault"), link, "dir");
        engine.declareDaemon({ protectedDirs: [declared], protectedFiles: [] });

        await expectRefusedWithOneNewRow(handle, `${link}/../declared/clone`, 0);

        expect(readdirSync(declared)).toEqual([]);
        expect(readdirSync(join(tempDir, "agent"))).toEqual(["link"]);
      },
    );

    it.each([
      ["a declared directory", (declared: string) => [declared]],
      ["two empty lists, as harpoc-mcp --http declares", () => []],
    ])(
      "after declareDaemon with %s a clone without a working directory is refused with one failed row",
      async (_label, protectedDirs) => {
        const handle = await gitSecret();
        engine.declareDaemon({
          protectedDirs: protectedDirs(join(tempDir, "declared")),
          protectedFiles: [],
        });

        const err = await expectVaultError(
          () => engine.useSecret(handle, CLONE_WITHOUT_DIRECTORY),
          ErrorCode.INVALID_GIT_CONFIG,
        );

        expect(err.message).toBe("working_directory is required for clone in a daemon");
        const rows = await useRows(handle);
        expect(rows).toHaveLength(1);
        expect(rows[0]?.success).toBe(false);
        expect(rows[0]?.detail).toEqual({
          context: "git",
          operation: "clone",
          error: ErrorCode.INVALID_GIT_CONFIG,
        });
        expect(spawnMock).not.toHaveBeenCalled();
      },
    );

    it("without declareDaemon a clone without a working directory is not refused: it goes on to its first step", async () => {
      const handle = await gitSecret();

      const result = await engine.useSecret(handle, CLONE_WITHOUT_DIRECTORY);

      expect(result).toMatchObject({ type: "git", exit_code: 1 });
      expect(spawnMock).toHaveBeenCalledTimes(1);
      const rows = await useRows(handle);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.detail?.error).not.toBe(ErrorCode.INVALID_GIT_CONFIG);
    });
  },
);
