import { execSync } from "node:child_process";
import {
  closeSync,
  existsSync,
  fsyncSync,
  openSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { readFile, chmod } from "node:fs/promises";
import { dirname, join } from "node:path";
import { randomFillSync } from "node:crypto";
import type { SessionFile } from "@harpoc/shared";
import {
  DEFAULT_SESSION_TTL_MS,
  MAX_SESSION_TTL_MS,
  VaultError,
  sessionFileSchema,
} from "@harpoc/shared";
import { wipeBuffer } from "../crypto/random.js";
import { createSessionKeyProtector } from "./session-key-protector.js";
import type { SessionKeyProtector } from "./session-key-protector.js";

export interface SessionManagerOptions {
  /** Session-key protector (default: platform-selected — DPAPI on Windows, none elsewhere). */
  protector?: SessionKeyProtector;
  /**
   * Invoked when session-file protection degrades at write time: keystore
   * wrapping failed (the file falls back to `key_protection: "none"`) or the
   * POSIX owner-only permission repair failed. The error message is
   * self-descriptive. Default: silent — core never logs; interactive entry
   * points (the CLI) supply a callback that surfaces the downgrade.
   */
  onProtectionFallback?: (error: Error) => void;
}

/**
 * Manages the session file at ~/.harpoc/session.json.
 *
 * - Atomic writes: write to .tmp, fsync, rename.
 * - Secure erase: overwrite with random bytes, fsync, unlink.
 * - Sliding window TTL with absolute ceiling.
 * - At rest, `session_key` is wrapped by the platform key store where one is
 *   implemented (thesis §4.6 off-host hardening); `key_protection` records the
 *   scheme so a copy of the file alone does not yield the session key.
 */
export class SessionManager {
  private static nextWriteId = 0;
  private readonly protector: SessionKeyProtector;
  private readonly onProtectionFallback: (error: Error) => void;

  constructor(
    private readonly sessionPath: string,
    options: SessionManagerOptions = {},
  ) {
    this.protector = options.protector ?? createSessionKeyProtector();
    this.onProtectionFallback = options.onProtectionFallback ?? ((): void => {});
  }

  /**
   * Write a new session file atomically with `session_key` wrapped by the
   * configured protector. The input's `session_key` must be the raw key; if
   * wrapping fails, the file is written unwrapped (`key_protection: "none"`)
   * and the fallback callback fires — availability over the optional hardening.
   */
  async writeSession(session: SessionFile): Promise<void> {
    let stored: SessionFile = { ...session, key_protection: "none" };

    if (this.protector.scheme !== "none") {
      // The raw key copy must be wiped on the failure path too — a throwing
      // protector must not leave it live in memory.
      let rawKey: Uint8Array | null = null;
      try {
        rawKey = new Uint8Array(Buffer.from(session.session_key, "base64"));
        const blob = await this.protector.protect(rawKey);
        stored = {
          ...session,
          session_key: Buffer.from(blob).toString("base64"),
          key_protection: this.protector.scheme,
        };
      } catch (err) {
        this.onProtectionFallback(
          new Error(
            `platform keystore unavailable — session file protected by file permissions only (${err instanceof Error ? err.message : String(err)})`,
          ),
        );
      } finally {
        if (rawKey) {
          wipeBuffer(rawKey);
        }
      }
    }

    await this.writeStoredSession(stored);
  }

  /**
   * Read and validate the session file, unwrapping `session_key`. Returns null
   * if the file is missing, expired, corrupted, wrapped under a scheme the
   * configured protector does not handle, or if unwrapping fails — fail closed;
   * a fresh unlock is the recovery path.
   */
  async readSession(): Promise<SessionFile | null> {
    const stored = await this.readStoredSession();
    if (!stored) return null;

    const scheme = stored.key_protection ?? "none";
    if (scheme === "none") {
      return stored;
    }
    if (scheme !== this.protector.scheme) {
      return null;
    }

    try {
      const raw = await this.protector.unprotect(
        new Uint8Array(Buffer.from(stored.session_key, "base64")),
      );
      const sessionKey = Buffer.from(raw).toString("base64");
      wipeBuffer(raw);
      return { ...stored, session_key: sessionKey, key_protection: "none" };
    } catch {
      return null;
    }
  }

  /**
   * Read and validate the session file as stored on disk. Returns null if
   * missing, expired, or corrupted. `session_key` is returned as stored — it
   * may be keystore-wrapped (see `key_protection`); use readSession() for the
   * raw key.
   */
  async readStoredSession(): Promise<SessionFile | null> {
    let raw: string;
    try {
      raw = await readFile(this.sessionPath, "utf8");
    } catch {
      return null; // File doesn't exist
    }

    // Parse JSON
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return null; // Corrupted JSON
    }

    // Validate schema
    const result = sessionFileSchema.safeParse(parsed);
    if (!result.success) {
      return null; // Invalid schema
    }

    const session = result.data;

    // Check expiry
    if (Date.now() > session.expires_at) {
      return null; // Expired
    }

    return session;
  }

  /**
   * Extend the session's expiry using a sliding window.
   * new_expires_at = min(now + ttl, max_expires_at)
   *
   * Operates on the stored form: the (possibly keystore-wrapped) session key is
   * carried over untouched, so the frequent monitor path never does a keystore
   * roundtrip. The returned file is the stored form.
   */
  async extendSession(
    ttlMs: number = DEFAULT_SESSION_TTL_MS,
    requireExisting = false,
  ): Promise<SessionFile | null> {
    const session = await this.readStoredSession();
    if (!session) return null;

    const now = Date.now();
    const newExpiresAt = Math.min(now + ttlMs, session.max_expires_at);

    // Don't write if the extension is negligible (< 1 second)
    if (newExpiresAt - session.expires_at < 1000) {
      return session;
    }

    const updated: SessionFile = {
      ...session,
      expires_at: newExpiresAt,
    };

    // requireExisting closes the slide/lock race: if a concurrent lock erased
    // the file between the read above and the rename below, the slide must not
    // resurrect it.
    const wrote = await this.writeStoredSession(updated, requireExisting);
    return wrote ? updated : null;
  }

  /**
   * Securely erase the session file: overwrite with random bytes, fsync, unlink.
   */
  async eraseSession(): Promise<void> {
    try {
      // Read file size
      const content = await readFile(this.sessionPath);

      // Overwrite with random bytes
      const randomData = Buffer.alloc(content.length);
      randomFillSync(randomData);
      writeFileSync(this.sessionPath, randomData);

      // fsync
      const fd = openSync(this.sessionPath, "r+");
      try {
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }

      // Delete
      unlinkSync(this.sessionPath);
    } catch {
      // If file doesn't exist, that's fine
      try {
        unlinkSync(this.sessionPath);
      } catch {
        // Already gone
      }
    }
  }

  /**
   * Write the session file exactly as given, atomically. The temp file is
   * created with mode 0o600 (POSIX: applied at creation and preserved by the
   * rename, so the raw session key is never readable by other users at any
   * instant — the trailing chmod is only a repair, and its failure fires the
   * fallback callback). The temp name is unique per write (pid + counter), so
   * overlapping writers — a use-driven expiry slide racing a session rewrite —
   * never share a temp file; last rename wins.
   *
   * With `requireExisting`, the rename is skipped (and the temp file removed)
   * if the session file has vanished — a concurrent lock erased it — so an
   * expiry slide can never resurrect a locked session. Returns whether the
   * file was written.
   */
  private async writeStoredSession(
    session: SessionFile,
    requireExisting = false,
  ): Promise<boolean> {
    const tmpPath = join(
      dirname(this.sessionPath),
      `.session.json.tmp.${process.pid}.${SessionManager.nextWriteId++}`,
    );

    try {
      const data = JSON.stringify(session, null, 2);
      writeFileSync(tmpPath, data, { encoding: "utf8", mode: 0o600 });

      // fsync the temp file
      const fd = openSync(tmpPath, "r+");
      try {
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }

      // Checked as close to the rename as possible: if the session file is
      // gone, do not recreate it. A microsecond check→rename window remains
      // (no cross-platform conditional rename exists) — the monitor backstops.
      if (requireExisting && !existsSync(this.sessionPath)) {
        unlinkSync(tmpPath);
        return false;
      }

      // Atomic rename
      renameSync(tmpPath, this.sessionPath);

      // Set file permissions: owner-only access
      if (process.platform === "win32") {
        try {
          execSync(`icacls "${this.sessionPath}" /inheritance:r /grant:r "%USERNAME%:F"`, {
            stdio: "ignore",
            windowsHide: true,
          });
        } catch {
          // Best-effort: icacls may not be available
        }
      } else {
        await chmod(this.sessionPath, 0o600).catch((err: unknown) => {
          this.onProtectionFallback(
            new Error(
              `failed to restrict session file permissions to owner-only (${err instanceof Error ? err.message : String(err)})`,
            ),
          );
        });
      }

      return true;
    } catch (err) {
      // Clean up temp file on failure
      try {
        unlinkSync(tmpPath);
      } catch {
        // Ignore cleanup errors
      }

      if (err instanceof VaultError) throw err;
      throw VaultError.sessionFileError(
        `Failed to write session: ${err instanceof Error ? err.message : "unknown"}`,
      );
    }
  }

  /**
   * Create a new session with default TTL.
   */
  static createSessionData(
    sessionId: string,
    vaultId: string,
    sessionKey: string,
    wrappedKek: string,
    wrappedKekIv: string,
    wrappedKekTag: string,
    wrappedJwtKey: string,
    wrappedJwtKeyIv: string,
    wrappedJwtKeyTag: string,
    wrappedAuditKey: string,
    wrappedAuditKeyIv: string,
    wrappedAuditKeyTag: string,
    ttlMs: number = DEFAULT_SESSION_TTL_MS,
  ): SessionFile {
    const now = Date.now();
    return {
      version: 1,
      session_id: sessionId,
      vault_id: vaultId,
      created_at: now,
      expires_at: now + ttlMs,
      max_expires_at: now + MAX_SESSION_TTL_MS,
      session_key: sessionKey,
      wrapped_kek: wrappedKek,
      wrapped_kek_iv: wrappedKekIv,
      wrapped_kek_tag: wrappedKekTag,
      wrapped_jwt_key: wrappedJwtKey,
      wrapped_jwt_key_iv: wrappedJwtKeyIv,
      wrapped_jwt_key_tag: wrappedJwtKeyTag,
      wrapped_audit_key: wrappedAuditKey,
      wrapped_audit_key_iv: wrappedAuditKeyIv,
      wrapped_audit_key_tag: wrappedAuditKeyTag,
    };
  }
}
