import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode, VaultState } from "@harpoc/shared";
import { VaultEngine } from "../vault-engine.js";
import { SessionManager } from "./session-manager.js";
import type { SessionKeyProtector } from "./session-key-protector.js";
import { expectVaultError } from "@harpoc/test-utils";

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

interface Deferred {
  promise: Promise<void>;
  resolve: () => void;
}

function deferred(): Deferred {
  let resolve: () => void = () => undefined;
  const promise = new Promise<void>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

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

/**
 * D7 — a session file the engine did not write is not the engine's session.
 *
 * A second process unlocking the same vault replaces `session.json` with its
 * own `session_id`; a file downgraded to `key_protection: "none"` under a
 * keystore protector is R8/D54's sticky downgrade. Both used to sustain — and
 * be slid by — an engine holding the keys of a session that no longer exists.
 */
describe("engine session identity (D7)", () => {
  it("the monitor seals an engine whose session file now belongs to another session", async () => {
    const engine = new VaultEngine({ dbPath: join(dir, "v3.vault.db"), sessionPath });
    try {
      await engine.initVault("password");
      const file = JSON.parse(readFileSync(sessionPath, "utf8")) as Record<string, unknown>;
      file["session_id"] = "01890000-0000-7000-8000-00000000ffff";
      writeFileSync(sessionPath, JSON.stringify(file), "utf8");

      await (engine as unknown as { sessionMonitorTick: () => Promise<void> }).sessionMonitorTick();

      expect(engine.getState()).toBe(VaultState.SEALED);
    } finally {
      await engine.destroy();
    }
  });

  it("control: the monitor leaves an engine whose file only slid its expiry", async () => {
    const engine = new VaultEngine({ dbPath: join(dir, "v4.vault.db"), sessionPath });
    try {
      await engine.initVault("password");
      const file = JSON.parse(readFileSync(sessionPath, "utf8")) as Record<string, unknown>;
      file["expires_at"] = (file["expires_at"] as number) + 60_000;
      writeFileSync(sessionPath, JSON.stringify(file), "utf8");

      await (engine as unknown as { sessionMonitorTick: () => Promise<void> }).sessionMonitorTick();

      expect(engine.getState()).toBe(VaultState.UNLOCKED);
    } finally {
      await engine.destroy();
    }
  });

  it("a failed session rewrite in changePassword seals the engine", async () => {
    class FailAfterInitProtector implements SessionKeyProtector {
      readonly scheme = "dpapi" as const;
      failing = false;

      async protect(key: Uint8Array): Promise<Uint8Array> {
        if (this.failing) throw new Error("keystore helper timed out");
        return new Uint8Array(Buffer.concat([Buffer.from("WRAP:"), Buffer.from(key)]));
      }

      async unprotect(blob: Uint8Array): Promise<Uint8Array> {
        return new Uint8Array(Buffer.from(blob).subarray(5));
      }
    }

    const protector = new FailAfterInitProtector();
    const engine = new VaultEngine({
      dbPath: join(dir, "v5.vault.db"),
      sessionPath,
      sessionKeyProtector: protector,
    });
    try {
      await engine.initVault("password");
      protector.failing = true;

      await expectVaultError(
        () => engine.changePassword("password", "new-password"),
        ErrorCode.SESSION_KEYSTORE_UNAVAILABLE,
      );

      expect(engine.getState()).toBe(VaultState.SEALED);
    } finally {
      await engine.destroy();
    }
  });

  it("a monitor tick during changePassword's session rewrite does not seal the engine", async () => {
    const wrapEntered = deferred();
    const releaseWrap = deferred();

    class GatedProtector implements SessionKeyProtector {
      readonly scheme = "dpapi" as const;
      gated = false;

      async protect(key: Uint8Array): Promise<Uint8Array> {
        if (this.gated) {
          this.gated = false;
          wrapEntered.resolve();
          await releaseWrap.promise;
        }
        return new Uint8Array(Buffer.concat([Buffer.from("WRAP:"), Buffer.from(key)]));
      }

      async unprotect(blob: Uint8Array): Promise<Uint8Array> {
        return new Uint8Array(Buffer.from(blob).subarray(5));
      }
    }

    const protector = new GatedProtector();
    const engine = new VaultEngine({
      dbPath: join(dir, "v6.vault.db"),
      sessionPath,
      sessionKeyProtector: protector,
    });
    try {
      await engine.initVault("password");
      protector.gated = true;

      const change = engine.changePassword("password", "new-password");
      // The wrap is now suspended between the new session_id assignment and the
      // rename, so the file on disk is still the old session: the window the
      // 30 s monitor interval can land in.
      await wrapEntered.promise;

      await (engine as unknown as { sessionMonitorTick: () => Promise<void> }).sessionMonitorTick();

      releaseWrap.resolve();
      await change;

      expect(engine.getState()).toBe(VaultState.UNLOCKED);
      expect(engine.listSecrets()).toEqual([]);
    } finally {
      await engine.destroy();
    }
  });
});
