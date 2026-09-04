import { spawnSync } from "node:child_process";
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  renameSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { readFile, chmod } from "node:fs/promises";
import { userInfo } from "node:os";
import { dirname, join } from "node:path";
import { randomFillSync } from "node:crypto";
import type { SessionFile } from "@harpoc/shared";
import {
  DEFAULT_SESSION_TTL_MS,
  MAX_SESSION_TTL_MS,
  SESSION_LOCK_POLL_MS,
  SESSION_LOCK_STALE_MS,
  VaultError,
  sessionFileSchema,
} from "@harpoc/shared";
import { wipeBuffer } from "../crypto/random.js";
import { system32Path } from "../win32-paths.js";
import { createSessionKeyProtector } from "./session-key-protector.js";
import type { SessionKeyProtector } from "./session-key-protector.js";

export interface SessionManagerOptions {
  /** Session-key protector (default: platform-selected — DPAPI on Windows, none elsewhere). */
  protector?: SessionKeyProtector;
  /**
   * Invoked when the owner-only permission repair after a write failed — the
   * POSIX chmod or the Windows icacls step; the file itself is created with
   * mode 0o600 from the first instant. The error message is self-descriptive.
   * Default: silent — core never logs; interactive entry points (the CLI)
   * supply a callback that surfaces the warning. A keystore failure is not a
   * warning: `writeSession` throws `SESSION_KEYSTORE_UNAVAILABLE` (R8/D54).
   */
  onPermissionRepairFailure?: (error: Error) => void;
  /**
   * Age after which a `session.json.lock` left behind by a dead process is
   * reclaimed (default `SESSION_LOCK_STALE_MS`; a test seam).
   */
  lockStaleMs?: number;
}

/** Does this read failure mean the session file is genuinely absent? */
function isMissingFileError(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException | null)?.code;
  return code === "ENOENT" || code === "ENOTDIR";
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

type SessionLockMode<T> = { mode: "wait" } | { mode: "try"; onContention: () => Promise<T> };

/**
 * Manages the session file at ~/.harpoc/session.json.
 *
 * - Atomic writes: write to .tmp, fsync, rename.
 * - Secure erase: overwrite with random bytes, fsync, unlink.
 * - Sliding window TTL with absolute ceiling.
 * - A `session.json.lock` directory beside the file serialises the slide, the
 *   fresh write and the erase across processes (R8/D56): `mkdir` is atomic
 *   on every platform, so no native addon is needed.
 * - At rest, `session_key` is wrapped by the platform key store where one is
 *   implemented (thesis §4.6 off-host hardening); `key_protection` records the
 *   scheme so a copy of the file alone does not yield the session key.
 */
export class SessionManager {
  private static nextWriteId = 0;
  private readonly protector: SessionKeyProtector;
  private readonly onPermissionRepairFailure: (error: Error) => void;
  private readonly lockPath: string;
  private readonly lockStaleMs: number;

  constructor(
    private readonly sessionPath: string,
    options: SessionManagerOptions = {},
  ) {
    this.protector = options.protector ?? createSessionKeyProtector();
    this.onPermissionRepairFailure = options.onPermissionRepairFailure ?? ((): void => {});
    this.lockPath = `${sessionPath}.lock`;
    this.lockStaleMs = options.lockStaleMs ?? SESSION_LOCK_STALE_MS;
  }

  /**
   * Write a new session file atomically with `session_key` wrapped by the
   * configured protector. The input's `session_key` must be the raw key. A
   * protector failure is fatal (R8/D54): nothing is written and the caller
   * gets `SESSION_KEYSTORE_UNAVAILABLE`, whose message names
   * `HARPOC_SESSION_KEYSTORE=off` as the explicit opt-out — the file never
   * silently downgrades to `key_protection: "none"`.
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
        throw VaultError.sessionKeystoreUnavailable(
          this.protector.scheme,
          err instanceof Error ? err.message : String(err),
        );
      } finally {
        if (rawKey) {
          wipeBuffer(rawKey);
        }
      }
    }

    await this.withSessionLock({ mode: "wait" }, () => this.writeStoredSession(stored));
  }

  /**
   * Read and validate the session file, unwrapping `session_key`. Returns null
   * if the file is missing, expired, corrupted, wrapped under a scheme the
   * configured protector does not handle, tagged `none` while a keystore
   * protector is configured (R8/D54 — a downgrade, not a session), or if
   * unwrapping fails — fail closed; a fresh unlock is the recovery path.
   */
  async readSession(): Promise<SessionFile | null> {
    // A load attempt tears nothing down, so a transient read failure degrades
    // to "no session" here — unlike the monitor and the slide, which must not
    // read an EMFILE as proof the session is gone (L6).
    let stored: SessionFile | null;
    try {
      stored = await this.readStoredSession();
    } catch {
      return null;
    }
    if (!stored) return null;

    const scheme = stored.key_protection;
    if (scheme === "none") {
      // Legitimate only where no keystore is selected — no platform tier, or
      // HARPOC_SESSION_KEYSTORE=off chose the none protector at construction.
      // Under a keystore protector it is the sticky downgrade N7 described.
      return this.protector.scheme === "none" ? stored : null;
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
   *
   * Throws `SESSION_FILE_ERROR` when the file exists but could not be read
   * (EMFILE, EIO, EACCES, EBUSY, …). Only an ENOENT-class failure means the
   * session is gone: both consumers treat null as proof of that and tear the
   * engine down — a transient error used to seal a live vault, wipe the KEK
   * and kill downstream children while the on-disk session was intact (L6).
   */
  async readStoredSession(): Promise<SessionFile | null> {
    let raw: string;
    try {
      raw = await readFile(this.sessionPath, "utf8");
    } catch (err) {
      if (isMissingFileError(err)) return null;
      throw VaultError.sessionFileError(
        `Failed to read session: ${err instanceof Error ? err.message : "unknown"}`,
      );
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
   *
   * The read, the check and the rename run under the session mutex (R8/D56),
   * so a lock or a fresh unlock in another process cannot interleave. A slide
   * is expendable: on contention the file is returned as stored and the next
   * throttled slide retries — a skip is never a "session gone" signal.
   */
  async extendSession(
    ttlMs: number = DEFAULT_SESSION_TTL_MS,
    requireExisting = false,
  ): Promise<SessionFile | null> {
    return this.withSessionLock(
      { mode: "try", onContention: () => this.readStoredSession() },
      async () => {
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

        const wrote = await this.writeStoredSession(updated, requireExisting);
        return wrote ? updated : null;
      },
    );
  }

  /**
   * Securely erase the session file: overwrite with random bytes, fsync, unlink.
   */
  async eraseSession(): Promise<void> {
    await this.withSessionLock({ mode: "wait" }, async () => {
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
    });
  }

  /**
   * Write the session file exactly as given, atomically. The temp file is
   * created with mode 0o600 (POSIX: applied at creation and preserved by the
   * rename, so the raw session key is never readable by other users at any
   * instant — the trailing chmod is only a repair, and its failure fires the
   * permission-repair callback). The temp name is unique per write (pid + counter), so
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

      // Under the session mutex this check cannot race a cross-process erase
      // any more (R8/D56); it stays as the guard for a writer that reached
      // here without the lock — the bounded wait that proceeded unlocked.
      if (requireExisting && !existsSync(this.sessionPath)) {
        unlinkSync(tmpPath);
        return false;
      }

      // Atomic rename
      renameSync(tmpPath, this.sessionPath);

      // Set file permissions: owner-only access
      if (process.platform === "win32") {
        this.restrictWindowsAcl();
      } else {
        await chmod(this.sessionPath, 0o600).catch((err: unknown) => {
          this.onPermissionRepairFailure(
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
   * Reduce the session file's ACL to the current user (the Windows counterpart
   * of the POSIX 0600 chmod).
   *
   * `icacls` is invoked through the pinned System32 path with `shell:false` and
   * the vault path as an *argument* — the previous `execSync` built a cmd.exe
   * string with the path interpolated into it, against the project's own
   * "never a shell; args are data" doctrine, and swallowed every failure while
   * the POSIX sibling reported through the permission-repair callback. The ACL
   * is the file's on-host protection beside the DPAPI wrap, so a failed
   * restriction is reported, not swallowed. `%USERNAME%` was a cmd.exe
   * expansion and cannot survive the shell's removal, so the account name
   * comes from the process itself.
   */
  private restrictWindowsAcl(): void {
    const icacls = system32Path("icacls.exe");
    try {
      const account = userInfo().username;
      if (!account) throw new Error("could not determine the current account name");
      const res = spawnSync(
        icacls,
        [this.sessionPath, "/inheritance:r", "/grant:r", `${account}:F`],
        { shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"], timeout: 15_000 },
      );
      if (res.error) throw res.error;
      if (res.status !== 0) {
        const detail = (res.stderr?.toString() || res.stdout?.toString() || "")
          .trim()
          .slice(0, 200);
        throw new Error(`icacls exited ${String(res.status)}${detail ? `: ${detail}` : ""}`);
      }
    } catch (err) {
      this.onPermissionRepairFailure(
        new Error(
          `failed to restrict session file permissions to owner-only (${err instanceof Error ? err.message : String(err)})`,
        ),
      );
    }
  }

  /**
   * The cross-process session mutex (R8/D56): `session.json.lock` is a
   * directory, because `mkdir` fails atomically on EEXIST on every platform.
   * `try` gives up at once and runs `onContention` (the slide is expendable);
   * `wait` polls until the lock is free or a holder older than `lockStaleMs`
   * is reclaimed, and past that bound proceeds without it — the fresh write
   * and the erase must never hang on a directory nobody can release. Any
   * other `mkdir` failure counts as "not acquired": the write that follows
   * reports the real error.
   */
  private async withSessionLock<T>(lock: SessionLockMode<T>, body: () => Promise<T>): Promise<T> {
    let held = this.tryAcquireLock();
    if (!held) {
      if (lock.mode === "try") return lock.onContention();
      const deadline = Date.now() + this.lockStaleMs + SESSION_LOCK_POLL_MS;
      while (!held && Date.now() < deadline) {
        await sleep(SESSION_LOCK_POLL_MS);
        held = this.tryAcquireLock();
      }
      // One attempt at or past the bound: a dead holder is reclaimed however
      // long the attempts themselves took.
      if (!held) held = this.tryAcquireLock();
    }
    try {
      return await body();
    } finally {
      if (held) this.releaseLock();
    }
  }

  private tryAcquireLock(): boolean {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        mkdirSync(this.lockPath);
        return true;
      } catch (err) {
        if ((err as NodeJS.ErrnoException | null)?.code !== "EEXIST") return false;
        if (!this.isLockStale()) return false;
        try {
          rmdirSync(this.lockPath);
        } catch {
          // Another process reclaimed it first; the retry decides.
        }
      }
    }
    return false;
  }

  private isLockStale(): boolean {
    try {
      return Date.now() - statSync(this.lockPath).mtimeMs > this.lockStaleMs;
    } catch {
      return false;
    }
  }

  private releaseLock(): void {
    try {
      rmdirSync(this.lockPath);
    } catch {
      // Already reclaimed as stale by another process.
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
      key_protection: "none",
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
