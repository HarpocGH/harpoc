import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode, VaultState } from "@harpoc/shared";
import { VaultEngine } from "../vault-engine.js";
import { SessionManager } from "./session-manager.js";

/**
 * L6 — a session-file read failure is not proof the session is gone.
 *
 * `readStoredSession` mapped every `readFile` rejection to null, and both
 * consumers treat null as "the session ended": the monitor sealed the engine,
 * wiped the KEK and killed downstream children, and the expiry slide marked the
 * session expired. A transient EMFILE/EIO/EACCES/EBUSY therefore tore down a
 * live vault while the on-disk session was intact and unexpired.
 */

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return { ...actual, readFile: vi.fn(actual.readFile) };
});

vi.mock("../crypto/argon2.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../crypto/argon2.js")>();
  return {
    ...original,
    deriveKey: async (password: string, salt: Uint8Array) => {
      const { createHash } = await import("node:crypto");
      return new Uint8Array(createHash("sha256").update(password).update(salt).digest());
    },
  };
});

function ioError(code: string): NodeJS.ErrnoException {
  const err = new Error(`${code}: injected`) as NodeJS.ErrnoException;
  err.code = code;
  return err;
}

let dir: string;
let sessionPath: string;

beforeEach(() => {
  vi.clearAllMocks();
  dir = join(tmpdir(), `harpoc-io-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });
  sessionPath = join(dir, "session.json");
});

afterEach(() => {
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
});

describe("SessionManager transient read failures (L6)", () => {
  it("throws SESSION_FILE_ERROR instead of reporting the session as absent", async () => {
    vi.mocked(readFile).mockRejectedValueOnce(ioError("EMFILE"));
    await expect(new SessionManager(sessionPath).readStoredSession()).rejects.toMatchObject({
      code: ErrorCode.SESSION_FILE_ERROR,
    });
  });

  it("control: ENOENT still means the session is gone", async () => {
    expect(await new SessionManager(sessionPath).readStoredSession()).toBeNull();
  });

  it("control: a corrupted file still reads as no session", async () => {
    writeFileSync(sessionPath, "{ not json");
    expect(await new SessionManager(sessionPath).readStoredSession()).toBeNull();
  });

  it("readSession degrades to null — a load attempt tears nothing down", async () => {
    vi.mocked(readFile).mockRejectedValueOnce(ioError("EIO"));
    expect(await new SessionManager(sessionPath).readSession()).toBeNull();
  });
});

describe("engine session monitor under a transient read failure (L6)", () => {
  it("keeps a live vault unlocked when the session file cannot be read", async () => {
    const engine = new VaultEngine({ dbPath: join(dir, "v.vault.db"), sessionPath });
    try {
      await engine.initVault("password");
      await engine.createSecret({
        name: "still-here",
        type: "api_key",
        value: new Uint8Array(Buffer.from("v")),
      });

      vi.mocked(readFile).mockRejectedValueOnce(ioError("EMFILE"));
      await (engine as unknown as { sessionMonitorTick: () => Promise<void> }).sessionMonitorTick();

      expect(engine.getState()).toBe(VaultState.UNLOCKED);
      // The KEK survived: the secret still decrypts.
      const value = await engine.getSecretValue("secret://still-here");
      expect(Buffer.from(value).toString()).toBe("v");
    } finally {
      await engine.destroy();
    }
  });

  it("control: a genuinely erased session file still seals the engine", async () => {
    const engine = new VaultEngine({ dbPath: join(dir, "v2.vault.db"), sessionPath });
    try {
      await engine.initVault("password");
      rmSync(sessionPath, { force: true });

      await (engine as unknown as { sessionMonitorTick: () => Promise<void> }).sessionMonitorTick();

      expect(engine.getState()).toBe(VaultState.SEALED);
    } finally {
      await engine.destroy();
    }
  });
});
