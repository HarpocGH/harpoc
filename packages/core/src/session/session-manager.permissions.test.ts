import { spawnSync } from "node:child_process";
import { mkdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { chmod } from "node:fs/promises";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SessionFile } from "@harpoc/shared";
import { DEFAULT_SESSION_TTL_MS, MAX_SESSION_TTL_MS } from "@harpoc/shared";
import { SessionManager } from "./session-manager.js";

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, writeFileSync: vi.fn(actual.writeFileSync) };
});

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawnSync: vi.fn(actual.spawnSync) };
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
    key_protection: "none",
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

  // L9: the ACL step used execSync with a cmd.exe string carrying the vault
  // path — against the project's own "never a shell; args are data" doctrine —
  // and swallowed every failure, on the very path whose stated protection is
  // file permissions (the DPAPI write-failure fallback).
  describe("Windows ACL step (L9)", () => {
    it("invokes the pinned System32 icacls with the path as an argument, no shell", async () => {
      await withPlatform("win32", async () => {
        vi.mocked(spawnSync).mockReturnValue({
          status: 0,
          signal: null,
          output: [],
          pid: 1,
          stdout: Buffer.from(""),
          stderr: Buffer.from(""),
        } as unknown as ReturnType<typeof spawnSync>);

        await new SessionManager(sessionPath).writeSession(makeValidSession());

        const call = vi.mocked(spawnSync).mock.calls.at(-1);
        expect(String(call?.[0])).toMatch(/[\\/]System32[\\/]icacls\.exe$/i);
        const args = call?.[1] as string[];
        expect(args[0]).toBe(sessionPath);
        expect(args).toContain("/inheritance:r");
        expect(call?.[2]).toMatchObject({ shell: false });
        // No account placeholder survives: %USERNAME% was a cmd.exe expansion.
        expect(args.join(" ")).not.toContain("%USERNAME%");
      });
    });

    it("a path with shell metacharacters cannot alter the argument vector", async () => {
      // Legal Windows filename, hostile cmd.exe string: the space splits, `&`
      // chains a second command and `%USERNAME%` was expanded by the old shell.
      const trickyDir = join(sessionDir, "we ird&dir %USERNAME%");
      mkdirSync(trickyDir, { recursive: true });
      const trickyPath = join(trickyDir, "session.json");

      await withPlatform("win32", async () => {
        vi.mocked(spawnSync).mockReturnValue({
          status: 0,
          signal: null,
          output: [],
          pid: 1,
          stdout: Buffer.from(""),
          stderr: Buffer.from(""),
        } as unknown as ReturnType<typeof spawnSync>);

        await new SessionManager(trickyPath).writeSession(makeValidSession());

        const args = vi.mocked(spawnSync).mock.calls.at(-1)?.[1] as string[];
        expect(args[0]).toBe(trickyPath);
        expect(args).toHaveLength(4);
      });
    });

    it("reports a failed ACL restriction through onProtectionFallback", async () => {
      await withPlatform("win32", async () => {
        vi.mocked(spawnSync).mockReturnValue({
          status: 5,
          signal: null,
          output: [],
          pid: 1,
          stdout: Buffer.from(""),
          stderr: Buffer.from("Access is denied."),
        } as unknown as ReturnType<typeof spawnSync>);

        const fallbacks: Error[] = [];
        const manager = new SessionManager(sessionPath, {
          onProtectionFallback: (err) => fallbacks.push(err),
        });
        await manager.writeSession(makeValidSession());

        expect(fallbacks).toHaveLength(1);
        expect(fallbacks[0]?.message).toContain("session file permissions");
        // The session itself is still written — availability over hardening.
        expect(await manager.readSession()).not.toBeNull();
      });
    });

    it.runIf(process.platform === "win32")(
      "real path: the ACL is reduced to the current user",
      async () => {
        vi.mocked(spawnSync).mockImplementation(
          (await vi.importActual<typeof import("node:child_process")>("node:child_process"))
            .spawnSync,
        );
        const fallbacks: Error[] = [];
        await new SessionManager(sessionPath, {
          onProtectionFallback: (err) => fallbacks.push(err),
        }).writeSession(makeValidSession());
        expect(fallbacks).toHaveLength(0);

        const real =
          await vi.importActual<typeof import("node:child_process")>("node:child_process");
        const listed = real.spawnSync(
          join(process.env.SystemRoot ?? "C:\\Windows", "System32", "icacls.exe"),
          [sessionPath],
          { shell: false, windowsHide: true },
        );
        const acl = listed.stdout?.toString() ?? "";
        expect(acl).toContain(userInfo().username);
        expect(acl).not.toMatch(/BUILTIN\\(Users|Benutzer)/);
      },
    );
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
