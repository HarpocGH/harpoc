import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
  statSync,
  readdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { SessionFile } from "@harpoc/shared";
import { DEFAULT_SESSION_TTL_MS, MAX_SESSION_TTL_MS } from "@harpoc/shared";
import { SessionManager } from "./session-manager.js";
import type { SessionKeyProtector } from "./session-key-protector.js";

let sessionDir: string;
let sessionPath: string;
let manager: SessionManager;

function makeValidSession(overrides: Partial<SessionFile> = {}): SessionFile {
  const now = Date.now();
  const b64 = Buffer.from('a]$%^&*(){}:";<>?/.,test').toString("base64");
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
    ...overrides,
  };
}

beforeEach(() => {
  sessionDir = join(tmpdir(), `harpoc-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(sessionDir, { recursive: true });
  sessionPath = join(sessionDir, "session.json");
  manager = new SessionManager(sessionPath);
});

afterEach(() => {
  // Clean up
  try {
    rmSync(sessionDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
});

describe("writeSession / readSession roundtrip", () => {
  it("writes and reads back a valid session", async () => {
    const session = makeValidSession();
    await manager.writeSession(session);

    const read = await manager.readSession();
    expect(read).not.toBeNull();
    expect(read?.session_id).toBe("test-session");
    expect(read?.vault_id).toBe("test-vault");
  });

  it("creates the file atomically", async () => {
    const session = makeValidSession();
    await manager.writeSession(session);
    expect(existsSync(sessionPath)).toBe(true);
  });
});

describe("readSession", () => {
  it("returns null for missing file", async () => {
    const result = await manager.readSession();
    expect(result).toBeNull();
  });

  it("returns null for corrupted JSON", async () => {
    writeFileSync(sessionPath, "not-json{{{", "utf8");
    const result = await manager.readSession();
    expect(result).toBeNull();
  });

  it("returns null for invalid schema", async () => {
    writeFileSync(sessionPath, JSON.stringify({ version: 99 }), "utf8");
    const result = await manager.readSession();
    expect(result).toBeNull();
  });

  it("returns null for expired session", async () => {
    const session = makeValidSession({ expires_at: Date.now() - 1000 });
    await manager.writeSession(session);

    const result = await manager.readSession();
    expect(result).toBeNull();
  });
});

describe("extendSession", () => {
  it("extends the expiry", async () => {
    const now = Date.now();
    const session = makeValidSession({ expires_at: now + 5000 });
    await manager.writeSession(session);

    const extended = await manager.extendSession(DEFAULT_SESSION_TTL_MS);
    expect(extended).not.toBeNull();
    expect(extended?.expires_at).toBeGreaterThan(now + 5000);
  });

  it("caps at max_expires_at", async () => {
    const now = Date.now();
    const session = makeValidSession({
      expires_at: now + 5000,
      max_expires_at: now + 10000,
    });
    await manager.writeSession(session);

    // Try to extend by a very long TTL
    const extended = await manager.extendSession(MAX_SESSION_TTL_MS);
    expect(extended).not.toBeNull();
    expect(extended?.expires_at).toBeLessThanOrEqual(now + 10000);
  });

  it("returns null for missing session", async () => {
    const result = await manager.extendSession();
    expect(result).toBeNull();
  });

  it("returns null for expired session", async () => {
    const session = makeValidSession({ expires_at: Date.now() - 1000 });
    await manager.writeSession(session);

    const result = await manager.extendSession();
    expect(result).toBeNull();
  });
});

describe("eraseSession", () => {
  it("deletes the session file", async () => {
    const session = makeValidSession();
    await manager.writeSession(session);
    expect(existsSync(sessionPath)).toBe(true);

    await manager.eraseSession();
    expect(existsSync(sessionPath)).toBe(false);
  });

  it("does not throw for missing file", async () => {
    await expect(manager.eraseSession()).resolves.not.toThrow();
  });
});

describe("createSessionData", () => {
  it("creates a session with correct structure", () => {
    const b64 = Buffer.from("test").toString("base64");
    const session = SessionManager.createSessionData(
      "sid",
      "vid",
      b64,
      b64,
      b64,
      b64,
      b64,
      b64,
      b64,
      b64,
      b64,
      b64,
    );

    expect(session.version).toBe(1);
    expect(session.session_id).toBe("sid");
    expect(session.vault_id).toBe("vid");
    expect(session.expires_at).toBeGreaterThan(session.created_at);
    expect(session.max_expires_at).toBeGreaterThan(session.expires_at);
    expect(session.max_expires_at - session.created_at).toBe(MAX_SESSION_TTL_MS);
    expect(session.wrapped_audit_key).toBe(b64);
  });

  it("accepts custom TTL", () => {
    const b64 = Buffer.from("test").toString("base64");
    const session = SessionManager.createSessionData(
      "sid",
      "vid",
      b64,
      b64,
      b64,
      b64,
      b64,
      b64,
      b64,
      b64,
      b64,
      b64,
      5000,
    );

    expect(session.expires_at - session.created_at).toBe(5000);
  });
});

describe("file permissions", () => {
  it("session file has mode 0o600 after write (Unix only)", async () => {
    if (process.platform === "win32") return; // Skip on Windows
    const session = makeValidSession();
    await manager.writeSession(session);

    const stats = statSync(sessionPath);
    // 0o600 = owner read/write only
    expect(stats.mode & 0o777).toBe(0o600);
  });

  it("session file permissions set via icacls on Windows (Windows only)", async () => {
    if (process.platform !== "win32") return; // Skip on non-Windows
    const session = makeValidSession();
    // writeSession internally calls icacls on Windows — should not throw
    await manager.writeSession(session);
    expect(existsSync(sessionPath)).toBe(true);
  });
});

describe("secure erase", () => {
  it("file is deleted after eraseSession", async () => {
    const session = makeValidSession();
    await manager.writeSession(session);
    expect(existsSync(sessionPath)).toBe(true);

    await manager.eraseSession();
    expect(existsSync(sessionPath)).toBe(false);
  });

  it("eraseSession is idempotent (double-call does not throw)", async () => {
    const session = makeValidSession();
    await manager.writeSession(session);

    await manager.eraseSession();
    await expect(manager.eraseSession()).resolves.not.toThrow();
  });

  it("after erase, no tmp files remain in the directory", async () => {
    const session = makeValidSession();
    await manager.writeSession(session);
    await manager.eraseSession();

    const remaining = readdirSync(sessionDir).filter((f) => f.includes(".tmp"));
    expect(remaining).toHaveLength(0);
  });
});

describe("session-key protection", () => {
  class FakeKeystoreProtector implements SessionKeyProtector {
    readonly scheme = "dpapi" as const;
    protectCalls = 0;
    unprotectCalls = 0;
    failProtect = false;
    failUnprotect = false;

    async protect(key: Uint8Array): Promise<Uint8Array> {
      this.protectCalls++;
      if (this.failProtect) throw new Error("keystore unavailable");
      return new Uint8Array(Buffer.concat([Buffer.from("WRAP:"), Buffer.from(key)]));
    }

    async unprotect(blob: Uint8Array): Promise<Uint8Array> {
      this.unprotectCalls++;
      if (this.failUnprotect) throw new Error("keystore unavailable");
      const buf = Buffer.from(blob);
      if (!buf.subarray(0, 5).equals(Buffer.from("WRAP:"))) throw new Error("not a wrapped blob");
      return new Uint8Array(buf.subarray(5));
    }
  }

  function readRawFile(): SessionFile {
    return JSON.parse(readFileSync(sessionPath, "utf8")) as SessionFile;
  }

  it("wraps the session key at rest and unwraps it on read", async () => {
    const protector = new FakeKeystoreProtector();
    const mgr = new SessionManager(sessionPath, { protector });
    const session = makeValidSession();

    await mgr.writeSession(session);

    const raw = readRawFile();
    expect(raw.key_protection).toBe("dpapi");
    expect(raw.session_key).not.toBe(session.session_key);
    expect(Buffer.from(raw.session_key, "base64").subarray(0, 5).toString()).toBe("WRAP:");

    const read = await mgr.readSession();
    expect(read?.session_key).toBe(session.session_key);
    expect(read?.key_protection).toBe("none");
    expect(protector.protectCalls).toBe(1);
    expect(protector.unprotectCalls).toBe(1);
  });

  it("readStoredSession returns the wrapped form without a keystore call", async () => {
    const protector = new FakeKeystoreProtector();
    const mgr = new SessionManager(sessionPath, { protector });
    const session = makeValidSession();
    await mgr.writeSession(session);

    const stored = await mgr.readStoredSession();
    expect(stored?.key_protection).toBe("dpapi");
    expect(stored?.session_key).not.toBe(session.session_key);
    expect(protector.unprotectCalls).toBe(0);
  });

  it("extendSession slides expiry without any keystore roundtrip", async () => {
    const protector = new FakeKeystoreProtector();
    const mgr = new SessionManager(sessionPath, { protector });
    const now = Date.now();
    const session = makeValidSession({ expires_at: now + 5000 });
    await mgr.writeSession(session);
    expect(protector.protectCalls).toBe(1);

    const extended = await mgr.extendSession(DEFAULT_SESSION_TTL_MS);
    expect(extended).not.toBeNull();
    expect(extended?.expires_at).toBeGreaterThan(now + 5000);
    expect(protector.protectCalls).toBe(1);
    expect(protector.unprotectCalls).toBe(0);

    const raw = readRawFile();
    expect(raw.key_protection).toBe("dpapi");
    const read = await mgr.readSession();
    expect(read?.session_key).toBe(session.session_key);
  });

  it("falls back to an unwrapped write when the keystore fails", async () => {
    const protector = new FakeKeystoreProtector();
    protector.failProtect = true;
    const fallbacks: Error[] = [];
    const mgr = new SessionManager(sessionPath, {
      protector,
      onProtectionFallback: (err) => fallbacks.push(err),
    });
    const session = makeValidSession();

    await mgr.writeSession(session);

    expect(fallbacks).toHaveLength(1);
    const raw = readRawFile();
    expect(raw.key_protection).toBe("none");
    expect(raw.session_key).toBe(session.session_key);
    expect((await mgr.readSession())?.session_key).toBe(session.session_key);
  });

  it("fails closed (null) when unwrapping fails", async () => {
    const protector = new FakeKeystoreProtector();
    const mgr = new SessionManager(sessionPath, { protector });
    await mgr.writeSession(makeValidSession());

    protector.failUnprotect = true;
    expect(await mgr.readSession()).toBeNull();
    expect(await mgr.readStoredSession()).not.toBeNull();
  });

  it("fails closed (null) when the stored scheme does not match the protector", async () => {
    const wrapped = new SessionManager(sessionPath, { protector: new FakeKeystoreProtector() });
    await wrapped.writeSession(makeValidSession());

    // The default manager in tests runs the none protector (HARPOC_SESSION_KEYSTORE=off).
    const plain = new SessionManager(sessionPath);
    expect(await plain.readSession()).toBeNull();
  });

  it("reads legacy files without key_protection as unwrapped", async () => {
    const protector = new FakeKeystoreProtector();
    const session = makeValidSession();
    writeFileSync(sessionPath, JSON.stringify(session, null, 2), "utf8");

    const mgr = new SessionManager(sessionPath, { protector });
    const read = await mgr.readSession();
    expect(read?.session_key).toBe(session.session_key);
    expect(protector.unprotectCalls).toBe(0);
  });

  it("reads none-tagged files under a keystore protector without unwrapping", async () => {
    const session = makeValidSession();
    await new SessionManager(sessionPath).writeSession(session);
    expect(readRawFile().key_protection).toBe("none");

    const protector = new FakeKeystoreProtector();
    const wrapped = new SessionManager(sessionPath, { protector });
    const read = await wrapped.readSession();
    expect(read?.session_key).toBe(session.session_key);
    expect(protector.unprotectCalls).toBe(0);
  });
});
