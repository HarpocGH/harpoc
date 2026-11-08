import { join } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SESSION_FILE_NAME, VAULT_DB_NAME } from "@harpoc/shared";

// ── Hoisted mocks: the engine's constructor records the options it receives ──

const { ctorCalls, fakeEngine } = vi.hoisted(() => ({
  ctorCalls: [] as Record<string, unknown>[],
  fakeEngine: {
    loadSession: vi.fn().mockResolvedValue(true),
    unlockWithKey: vi.fn().mockResolvedValue(undefined),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("@harpoc/core", () => ({
  VaultEngine: vi.fn().mockImplementation(function (options: Record<string, unknown>) {
    ctorCalls.push(options);
    return fakeEngine;
  }),
  wipeBuffer: (bytes: Uint8Array) => bytes.fill(0),
}));

import { createEngine, loadUnlockedEngine, unlockEngineWithKey } from "./vault-loader.js";

const VAULT = join("srv", "vault");
const PATHS = {
  dbPath: join(VAULT, VAULT_DB_NAME),
  sessionPath: join(VAULT, SESSION_FILE_NAME),
};
const CALLBACKS = {
  onSessionFilePermissionRepairFailure: expect.any(Function),
  onJobWrapperUnavailable: expect.any(Function),
};

describe("the engine options a command chooses (server start --session, B5)", () => {
  beforeEach(() => {
    ctorCalls.length = 0;
    vi.clearAllMocks();
  });

  // Model A untouched: without options every entry point builds the engine as before.
  it.each([
    { label: "createEngine", open: async () => createEngine(VAULT) },
    { label: "loadUnlockedEngine", open: () => loadUnlockedEngine(VAULT) },
    { label: "unlockEngineWithKey", open: () => unlockEngineWithKey(VAULT, new Uint8Array(32)) },
  ])("$label without options builds the engine with no sessionMode key", async ({ open }) => {
    await open();

    expect(ctorCalls).toEqual([{ ...PATHS, ...CALLBACKS }]);
    expect(Object.keys(ctorCalls[0] ?? {})).toEqual([
      "dbPath",
      "sessionPath",
      "onSessionFilePermissionRepairFailure",
      "onJobWrapperUnavailable",
    ]);
  });

  it.each(["memory", "file"] as const)(
    "createEngine(dir, { sessionMode: %j }) hands the mode to the engine",
    (sessionMode) => {
      createEngine(VAULT, { sessionMode });

      expect(ctorCalls).toEqual([{ ...PATHS, sessionMode, ...CALLBACKS }]);
    },
  );

  it("loadUnlockedEngine(dir, { sessionMode: 'memory' }) loads the session on a memory-mode engine", async () => {
    const engine = await loadUnlockedEngine(VAULT, { sessionMode: "memory" });

    expect(engine).toBe(fakeEngine);
    expect(ctorCalls).toEqual([{ ...PATHS, sessionMode: "memory", ...CALLBACKS }]);
    expect(fakeEngine.loadSession).toHaveBeenCalledTimes(1);
  });

  it("unlockEngineWithKey(dir, key, { sessionMode: 'memory' }) unlocks a memory-mode engine with the key and wipes it", async () => {
    const key = new Uint8Array(32).fill(7);

    const engine = await unlockEngineWithKey(VAULT, key, { sessionMode: "memory" });

    expect(engine).toBe(fakeEngine);
    expect(ctorCalls).toEqual([{ ...PATHS, sessionMode: "memory", ...CALLBACKS }]);
    expect(fakeEngine.unlockWithKey.mock.calls[0]?.[0] === key).toBe(true);
    expect(key.every((byte) => byte === 0)).toBe(true);
  });
});
