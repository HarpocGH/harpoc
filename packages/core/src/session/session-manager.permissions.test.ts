import { mkdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SessionFile } from "@harpoc/shared";
import { DEFAULT_SESSION_TTL_MS, MAX_SESSION_TTL_MS } from "@harpoc/shared";
import { SessionManager } from "./session-manager.js";

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, writeFileSync: vi.fn(actual.writeFileSync) };
});

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return { ...actual, chmod: vi.fn(actual.chmod) };
});

let sessionDir: string;
let sessionPath: string;

function makeValidSession(): SessionFile {
  const now = Date.now();
  const b64 = Buffer.from("permissions-test").toString("base64");
  return {
    version: 1,
    session_id: "test-session",
    vault_id: "test-vault",
    created_at: now,
    expires_at: now + DEFAULT_SESSION_TTL_MS,
    max_expires_at: now + MAX_SESSION_TTL_MS,
    session_key: b64,
    wrapped_kek: b64,
    wrapped_kek_iv: b64,
    wrapped_kek_tag: b64,
    wrapped_jwt_key: b64,
    wrapped_jwt_key_iv: b64,
    wrapped_jwt_key_tag: b64,
    wrapped_audit_key: b64,
    wrapped_audit_key_iv: b64,
    wrapped_audit_key_tag: b64,
  };
}

function withPlatform(platform: NodeJS.Platform, fn: () => Promise<void>): Promise<void> {
  const original = process.platform;
  Object.defineProperty(process, "platform", { value: platform, configurable: true });
  return fn().finally(() => {
    Object.defineProperty(process, "platform", { value: original, configurable: true });
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  sessionDir = join(tmpdir(), `harpoc-perm-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(sessionDir, { recursive: true });
  sessionPath = join(sessionDir, "session.json");
});

afterEach(() => {
  try {
    rmSync(sessionDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
});

describe("session file permissions (owner-only from creation)", () => {
  it("creates the temp file with mode 0o600 so the key is never world-readable", async () => {
    const manager = new SessionManager(sessionPath);
    await manager.writeSession(makeValidSession());

    const tmpWrite = vi
      .mocked(writeFileSync)
      .mock.calls.find(([path]) => String(path).includes(".session.json.tmp."));
    expect(tmpWrite).toBeDefined();
    expect(tmpWrite?.[2]).toMatchObject({ mode: 0o600 });
  });

  it("surfaces a failed permission repair via onProtectionFallback (POSIX branch)", async () => {
    await withPlatform("linux", async () => {
      vi.mocked(chmod).mockRejectedValueOnce(new Error("EPERM: operation not permitted"));
      const fallbacks: Error[] = [];
      const manager = new SessionManager(sessionPath, {
        onProtectionFallback: (err) => fallbacks.push(err),
      });

      await manager.writeSession(makeValidSession());

      expect(fallbacks).toHaveLength(1);
      expect(fallbacks[0]?.message).toContain("session file permissions");
      expect(await manager.readSession()).not.toBeNull();
    });
  });

  it.runIf(process.platform !== "win32")(
    "file is 0o600 on disk even when the trailing chmod fails",
    async () => {
      vi.mocked(chmod).mockRejectedValueOnce(new Error("EPERM: operation not permitted"));
      const fallbacks: Error[] = [];
      const manager = new SessionManager(sessionPath, {
        onProtectionFallback: (err) => fallbacks.push(err),
      });

      await manager.writeSession(makeValidSession());

      expect(statSync(sessionPath).mode & 0o777).toBe(0o600);
      expect(fallbacks).toHaveLength(1);
    },
  );
});
