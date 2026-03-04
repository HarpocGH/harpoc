import { execSync } from "node:child_process";
import { openSync, closeSync, fsyncSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
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

/**
 * Manages the session file at ~/.harpoc/session.json.
 *
 * - Atomic writes: write to .tmp, fsync, rename.
 * - Secure erase: overwrite with random bytes, fsync, unlink.
 * - Sliding window TTL with absolute ceiling.
 */
export class SessionManager {
  constructor(private readonly sessionPath: string) {}

  /**
   * Write a new session file atomically. Sets file permissions to 0o600.
   */
  async writeSession(session: SessionFile): Promise<void> {
    const tmpPath = join(
      dirname(this.sessionPath),
      `.session.json.tmp.${process.pid}`,
    );

    try {
      const data = JSON.stringify(session, null, 2);
      writeFileSync(tmpPath, data, "utf8");

      // fsync the temp file
      const fd = openSync(tmpPath, "r+");
      try {
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }

      // Atomic rename
      renameSync(tmpPath, this.sessionPath);

      // Set file permissions: owner-only access
      if (process.platform === "win32") {
        try {
          execSync(
            `icacls "${this.sessionPath}" /inheritance:r /grant:r "%USERNAME%:F"`,
            { stdio: "ignore", windowsHide: true },
          );
        } catch {
          // Best-effort: icacls may not be available
        }
      } else {
        await chmod(this.sessionPath, 0o600).catch(() => {});
      }
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
   * Read and validate the session file. Returns null if missing, expired, or corrupted.
   */
  async readSession(): Promise<SessionFile | null> {
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

    const session = result.data as SessionFile;

    // Check expiry
    if (Date.now() > session.expires_at) {
      return null; // Expired
    }

    return session;
  }

  /**
   * Extend the session's expiry using a sliding window.
   * new_expires_at = min(now + ttl, max_expires_at)
   */
  async extendSession(
    ttlMs: number = DEFAULT_SESSION_TTL_MS,
  ): Promise<SessionFile | null> {
    const session = await this.readSession();
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

    await this.writeSession(updated);
    return updated;
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
