import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SESSION_FILE_NAME, VAULT_DB_NAME } from "@harpoc/shared";
import { VaultEngine } from "@harpoc/core";

const { mockPromptPassword } = vi.hoisted(() => ({ mockPromptPassword: vi.fn() }));

vi.mock("../utils/prompt.js", () => ({ promptPassword: mockPromptPassword }));

import { registerInitCommand } from "./init.js";
import { registerUnlockCommand } from "./unlock.js";
import { registerLockCommand } from "./lock.js";
import { buildCli, spyCli, type CliSpies } from "../__fixtures__/cli-harness.js";

const PASSWORD = "vault-commands-pw-1";
const UUID_V7 = /[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/;

let tempDir: string;
let vaultDir: string;
let spies: CliSpies;

function run(args: string[]): Promise<void> {
  return buildCli(
    (program) => {
      registerInitCommand(program);
      registerUnlockCommand(program);
      registerLockCommand(program);
    },
    ["--vault-dir", vaultDir],
  )(args);
}

function answer(...values: string[]): void {
  for (const value of values) mockPromptPassword.mockResolvedValueOnce(value);
}

const dbPath = (): string => join(vaultDir, VAULT_DB_NAME);
const sessionPath = (): string => join(vaultDir, SESSION_FILE_NAME);

/** A vault created through the engine and left unlocked (initVault writes the session file). */
async function unlockedVault(): Promise<void> {
  mkdirSync(vaultDir, { recursive: true });
  const engine = new VaultEngine({ dbPath: dbPath(), sessionPath: sessionPath() });
  await engine.initVault(PASSWORD);
  await engine.destroy();
}

/** A vault created through the engine and sealed (lock erases the session file). */
async function sealedVault(): Promise<void> {
  mkdirSync(vaultDir, { recursive: true });
  const engine = new VaultEngine({ dbPath: dbPath(), sessionPath: sessionPath() });
  await engine.initVault(PASSWORD);
  await engine.lock();
  await engine.destroy();
}

beforeEach(() => {
  mockPromptPassword.mockReset();
  tempDir = join(tmpdir(), `harpoc-vc-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  vaultDir = join(tempDir, "vault");
  spies = spyCli();
});

afterEach(() => {
  spies.restore();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("harpoc init", () => {
  it("creates the vault and its session, prompting twice", async () => {
    answer(PASSWORD, PASSWORD);
    await run(["init"]);
    expect(spies.exitSpy).not.toHaveBeenCalled();
    expect(spies.errorSpy.mock.calls).toEqual([
      [expect.stringMatching(new RegExp(`^OK: Vault created \\(${UUID_V7.source}\\)$`))],
    ]);
    expect(mockPromptPassword.mock.calls).toEqual([
      ["Choose a master password: "],
      ["Confirm password: "],
    ]);
    expect(existsSync(dbPath())).toBe(true);
    expect(existsSync(sessionPath())).toBe(true);
  });

  it("refuses an existing vault before prompting and leaves its database untouched", async () => {
    await sealedVault();
    const before = readFileSync(dbPath());
    await expect(run(["init"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy.mock.calls[0]).toEqual([1]);
    expect(spies.errorSpy).toHaveBeenNthCalledWith(
      1,
      `Error: a vault already exists at ${dbPath()}.\n` +
        `Use 'harpoc unlock' to open it. To start over, delete the vault directory manually.`,
    );
    expect(mockPromptPassword).not.toHaveBeenCalled();
    expect(readFileSync(dbPath()).equals(before)).toBe(true);
  });

  it("refuses a mismatched confirmation and creates no database", async () => {
    answer(PASSWORD, "another-password");
    await expect(run(["init"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy.mock.calls[0]).toEqual([1]);
    expect(spies.errorSpy).toHaveBeenNthCalledWith(1, "Error: Passwords do not match.");
    expect(existsSync(dbPath())).toBe(false);
  });

  it("refuses an empty password before the confirmation and creates no database", async () => {
    answer("");
    await expect(run(["init"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy.mock.calls[0]).toEqual([1]);
    expect(spies.errorSpy).toHaveBeenNthCalledWith(1, "Error: Password cannot be empty.");
    expect(mockPromptPassword).toHaveBeenCalledTimes(1);
    expect(existsSync(dbPath())).toBe(false);
  });
});

describe("harpoc unlock", () => {
  it("writes the session file", async () => {
    await sealedVault();
    expect(existsSync(sessionPath())).toBe(false);
    answer(PASSWORD);
    await run(["unlock"]);
    expect(spies.exitSpy).not.toHaveBeenCalled();
    expect(spies.errorSpy.mock.calls).toEqual([["OK: Vault unlocked."]]);
    expect(mockPromptPassword.mock.calls).toEqual([[]]);
    expect(existsSync(sessionPath())).toBe(true);
  });

  it("refuses a wrong password and writes no session", async () => {
    await sealedVault();
    answer("wrong-password");
    await expect(run(["unlock"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(spies.errorSpy.mock.calls).toEqual([["Error: Invalid password."]]);
    expect(existsSync(sessionPath())).toBe(false);
  });

  it("locks the account out after five wrong passwords, the right one included", async () => {
    await sealedVault();
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      for (let attempt = 0; attempt < 5; attempt++) {
        answer("wrong-password");
        await expect(run(["unlock"])).rejects.toThrow("process.exit");
      }
      answer(PASSWORD);
      await expect(run(["unlock"])).rejects.toThrow("process.exit");
    } finally {
      vi.useRealTimers();
    }
    expect(spies.exitSpy.mock.calls).toEqual(Array.from({ length: 6 }, () => [1]));
    expect(spies.errorSpy.mock.calls).toEqual([
      ...Array.from({ length: 5 }, () => ["Error: Invalid password."]),
      ["Error: Account locked. Try again in 30s."],
    ]);
    expect(existsSync(sessionPath())).toBe(false);
  }, 60_000);
});

describe("harpoc lock", () => {
  it("erases the session file", async () => {
    await unlockedVault();
    expect(existsSync(sessionPath())).toBe(true);
    await run(["lock"]);
    expect(spies.exitSpy).not.toHaveBeenCalled();
    expect(spies.errorSpy.mock.calls).toEqual([["OK: Vault locked."]]);
    expect(existsSync(sessionPath())).toBe(false);
  });

  it("refuses a sealed vault", async () => {
    await sealedVault();
    await expect(run(["lock"])).rejects.toThrow("process.exit");
    expect(spies.exitSpy.mock.calls).toEqual([[1]]);
    expect(spies.errorSpy.mock.calls).toEqual([
      ["Error: Vault is locked. Run 'harpoc unlock' first."],
    ]);
    expect(existsSync(dbPath())).toBe(true);
  });
});
