import { chmodSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { expectAbsent } from "@harpoc/test-utils";

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, chmodSync: vi.fn() };
});

vi.mock("../utils/prompt.js", () => ({
  promptPassword: vi.fn().mockResolvedValue("correct horse battery staple"),
}));

vi.mock("../utils/vault-loader.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../utils/vault-loader.js")>();
  return {
    ...actual,
    createEngine: vi.fn(() => ({
      initVault: async () => ({ vaultId: "v" }),
      destroy: async () => {},
    })),
  };
});

import { registerInitCommand } from "./init.js";
import { buildCli, spyCli, type CliSpies } from "../__fixtures__/cli-harness.js";

const HELPER_TEXT = "helper-text-marker-3f9c";
const REAL_PLATFORM = process.platform;

const run = buildCli(registerInitCommand, ["init"]);

function stubPlatform(value: NodeJS.Platform): void {
  Object.defineProperty(process, "platform", { value, configurable: true });
}

describe("init: a failed owner-only chmod of the vault directory", () => {
  let spies: CliSpies;
  let vaultDir: string;

  beforeEach(() => {
    vi.mocked(chmodSync).mockReset();
    vaultDir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-init-chmod-")));
    spies = spyCli();
    stubPlatform("linux");
  });

  afterEach(() => {
    stubPlatform(REAL_PLATFORM);
    spies.restore();
    rmSync(vaultDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it.each([
    [
      "names node's errno code, never its text",
      Object.assign(new Error(`EPERM: operation not permitted, chmod '${HELPER_TEXT}'`), {
        code: "EPERM",
      }),
      "EPERM",
    ],
    [
      "names unknown error for an error without a code",
      new Error(`chmod failed ${HELPER_TEXT}`),
      "unknown error",
    ],
  ])("the warning %s", async (_case, failure, named) => {
    vi.mocked(chmodSync).mockImplementationOnce(() => {
      throw failure;
    });

    await run(["--vault-dir", vaultDir]);

    expectAbsent(spies.stderr(), HELPER_TEXT, "stderr");
    expect(spies.errorSpy.mock.calls).toEqual([
      [`Warning: could not restrict ${vaultDir} to owner-only access (${named})`],
      ["OK: Vault created (v)"],
    ]);
    expect(chmodSync).toHaveBeenCalledExactlyOnceWith(vaultDir, 0o700);
  });
});
