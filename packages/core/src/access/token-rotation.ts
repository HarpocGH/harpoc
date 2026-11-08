import { randomBytes } from "node:crypto";
import {
  closeSync,
  fchmodSync,
  fsyncSync,
  openSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { ErrorCode, MAX_TOKEN_TTL_MS, VaultError } from "@harpoc/shared";
import type { Permission, TokenPrincipalType } from "@harpoc/shared";

/** `token.jwt`'s mode (DB-14): the vault user writes, the consumer's group reads. */
const TOKEN_FILE_MODE = 0o640;

/** The `label` of every rotated token — `harpoc auth list` tells them from `auth token`'s. */
const TOKEN_ROTATION_LABEL = "rotation";

const MAX_TTL_MINUTES = MAX_TOKEN_TTL_MS / 60_000;

/**
 * win32: `rename` is `MoveFileExW(…, MOVEFILE_REPLACE_EXISTING)` (libuv `fs__rename`), which
 * fails `EPERM` while any handle holds the token file open — FILE_SHARE_DELETE or not (measured,
 * Node v24.13.1). A consumer's read closes at once; the rename is tried this often, this far
 * apart (about half a second), before the write is refused.
 */
export const WIN32_RENAME_ATTEMPTS = 20;
export const WIN32_RENAME_RETRY_MS = 25;
const WIN32_RENAME_RETRIED = new Set(["EPERM", "EBUSY", "EACCES"]);

/**
 * One `server start --issue-token` spec (DB-13): the registered agent the
 * token names, the file it is written to, the token's scope and secret-name
 * patterns, its lifetime in whole minutes (1–1440).
 */
export interface TokenRotationSpec {
  agent: string;
  file: string;
  scope: Permission[];
  secrets: string[];
  ttlMinutes: number;
}

/**
 * The engine surface the rotator uses — `createToken`, a member a
 * `VaultEngine` has; declared here so the scheduler depends on it, not on the
 * class (the egress proxy's `ProxyEngine`, the agent socket's
 * `AgentSocketEngine`). The engine judges every mint and writes its row.
 */
export interface TokenRotationEngine {
  createToken(
    subject: string,
    scope: Permission[],
    ttlMs: number,
    options: {
      secrets?: string[];
      principalType?: TokenPrincipalType;
      label?: string;
      rotation?: { previousJti?: string };
    },
  ): string;
}

export interface TokenRotationSchedulerOptions {
  /**
   * A spec stopped by a failed re-mint or write — the engine's `VaultError`
   * (a code and a value-free message), never the token. Default: no-op — core
   * is console-free; the CLI prints the code.
   */
  onError?: (spec: TokenRotationSpec, err: unknown) => void;
  /** A spec's file rewritten — the new token's `jti`, never the token. */
  onRotate?: (spec: TokenRotationSpec, jti: string) => void;
}

interface SpecState {
  readonly spec: TokenRotationSpec;
  live: boolean;
  timer: ReturnType<typeof setTimeout> | null;
  previousJti: string | undefined;
}

/**
 * The issuer-side token rotation of deployment model B (design § 3 M2,
 * DB-13): for each spec the daemon mints an agent token at `start()` and again
 * at 50 % of its lifetime, every time, and writes it atomically to the spec's
 * file — `0640`, the group of the set-group-ID consumer directory — where the
 * consumer re-reads it per call. A stolen file still dies at its `exp`
 * (≤ 24 h). A refused re-mint — the replaced token revoked (`TOKEN_REVOKED`),
 * the agent deactivated (`AGENT_INACTIVE`) or deleted (`AGENT_NOT_FOUND`) —
 * or a failed write stops that spec for good; a sealed engine
 * (`VAULT_LOCKED`) stops every spec. The engine audits each mint and each
 * refusal (`token.create`, `rotation: true`); nothing but the file ever holds
 * the token.
 */
export class TokenRotationScheduler {
  private readonly states: SpecState[];
  private running = false;

  constructor(
    private readonly engine: TokenRotationEngine,
    specs: readonly TokenRotationSpec[],
    private readonly options: TokenRotationSchedulerOptions = {},
  ) {
    const files = new Set<string>();
    for (const spec of specs) {
      const { ttlMinutes } = spec;
      if (!Number.isInteger(ttlMinutes) || ttlMinutes < 1 || ttlMinutes > MAX_TTL_MINUTES) {
        throw VaultError.invalidInput(
          `token rotation agent=${spec.agent}: ttl must be a whole number of minutes from 1 to ${MAX_TTL_MINUTES}`,
        );
      }
      const file = resolve(spec.file);
      if (files.has(file)) {
        throw VaultError.invalidInput(
          `token rotation agent=${spec.agent}: ${spec.file} is named by another spec; one token file per spec`,
        );
      }
      files.add(file);
    }
    this.states = specs.map((spec) => ({ spec, live: false, timer: null, previousJti: undefined }));
  }

  /**
   * Mint every spec's first token at once, before any listener accepts, and
   * arm each spec's re-mint. The first refusal or failed write rejects the
   * start with the engine's error and clears every armed timer; the files of
   * the specs before it keep the tokens they were given (each dies at its
   * `exp`, a restart re-mints over it). A start mints afresh, naming no
   * replaced token, as a daemon restart does; a second call while running is
   * a no-op.
   */
  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      for (const state of this.states) {
        if (!this.running) return;
        state.live = true;
        state.previousJti = undefined;
        const jti = this.mint(state);
        this.arm(state);
        this.notify(() => this.options.onRotate?.(state.spec, jti));
      }
    } catch (err) {
      this.halt();
      throw err;
    }
  }

  /** Clear every armed re-mint. A tick runs to completion synchronously, so none is ever in flight here. */
  async stop(): Promise<void> {
    this.halt();
  }

  /** Re-mint every live spec now and re-arm each from now — the test seam and an operator's nudge. */
  async rotateNow(): Promise<void> {
    for (const state of this.states) {
      if (!state.live) continue;
      if (state.timer !== null) clearTimeout(state.timer);
      this.tick(state);
    }
  }

  private tick(state: SpecState): void {
    state.timer = null;
    if (!state.live) return;
    let jti: string;
    try {
      jti = this.mint(state);
    } catch (err) {
      if (err instanceof VaultError && err.code === ErrorCode.VAULT_LOCKED) {
        this.halt();
      } else {
        state.live = false;
      }
      this.notify(() => this.options.onError?.(state.spec, err));
      return;
    }
    this.arm(state);
    this.notify(() => this.options.onRotate?.(state.spec, jti));
  }

  /**
   * The temporary is created before the mint, so a file that cannot be
   * written mints nothing (the `auth token --out` order); the `jti` is read
   * from the minted token's payload, which the engine signed.
   */
  private mint(state: SpecState): string {
    const { spec, previousJti } = state;
    const pending = openTokenFile(spec.file);
    let token: string;
    let jti: string;
    try {
      token = this.engine.createToken(spec.agent, spec.scope, spec.ttlMinutes * 60_000, {
        principalType: "agent",
        secrets: spec.secrets,
        label: TOKEN_ROTATION_LABEL,
        rotation: previousJti === undefined ? {} : { previousJti },
      });
      jti = jtiOf(token);
    } catch (err) {
      pending.discard();
      throw err;
    }
    pending.commit(token);
    state.previousJti = jti;
    return jti;
  }

  private arm(state: SpecState): void {
    if (!this.running || !state.live) return;
    const timer = setTimeout(() => this.tick(state), rotationDelayMs(state.spec.ttlMinutes));
    if (timer.unref) timer.unref();
    state.timer = timer;
  }

  private halt(): void {
    this.running = false;
    for (const state of this.states) {
      state.live = false;
      if (state.timer !== null) {
        clearTimeout(state.timer);
        state.timer = null;
      }
    }
  }

  /** A host callback that throws must not stop the rotation or escape a timer as an uncaught exception. */
  private notify(callback: () => void): void {
    try {
      callback();
    } catch {
      // The host's diagnostics channel failed; the rotation goes on.
    }
  }
}

/** 50 % of the token's lifetime (DB-13) — no jitter: one daemon, one timer per consumer. */
function rotationDelayMs(ttlMinutes: number): number {
  return Math.floor((ttlMinutes * 60_000) / 2);
}

function jtiOf(token: string): string {
  let jti: unknown;
  try {
    const payload = token.split(".")[1] ?? "";
    jti = (JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { jti?: unknown }).jti;
  } catch {
    jti = undefined;
  }
  if (typeof jti !== "string" || jti === "") {
    throw new VaultError(
      ErrorCode.INTERNAL_ERROR,
      "token rotation: the minted token carries no jti",
    );
  }
  return jti;
}

/** A write failure as the path and an errno code, never node's text or a byte of the token. */
function tokenFileError(path: string, err: unknown): VaultError {
  const code = err instanceof Error ? (err as NodeJS.ErrnoException).code : undefined;
  return new VaultError(
    ErrorCode.FILE_IO_ERROR,
    `could not write the token file ${path} (${code ?? "unknown error"})`,
  );
}

function unlinkQuietly(path: string): void {
  try {
    unlinkSync(path);
  } catch {
    // Best effort: the thrown error names the token file.
  }
}

function closeQuietly(fd: number): void {
  try {
    closeSync(fd);
  } catch {
    // Already closed or failing; the caller reports the write.
  }
}

/** A synchronous pause: the write runs inside the scheduler's synchronous tick. */
function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * `rename(tmp, path)`: once on POSIX; on win32 retried while another handle holds `path` open
 * (`WIN32_RENAME_ATTEMPTS` × `WIN32_RENAME_RETRY_MS`), the last errno thrown.
 */
function renameOver(tmp: string, path: string): void {
  if (process.platform !== "win32") {
    renameSync(tmp, path);
    return;
  }
  for (let attempt = 1; ; attempt += 1) {
    try {
      renameSync(tmp, path);
      return;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (
        attempt >= WIN32_RENAME_ATTEMPTS ||
        code === undefined ||
        !WIN32_RENAME_RETRIED.has(code)
      ) {
        throw err;
      }
      sleepSync(WIN32_RENAME_RETRY_MS);
    }
  }
}

interface PendingTokenFile {
  commit(token: string): void;
  discard(): void;
}

/**
 * Create the temporary `<path>.<12 hex>.tmp` beside `path` (a rename never
 * crosses a file system): `wx`, mode `0640`, on POSIX `fchmod(0640)` before
 * any byte because the umask may have narrowed the mode at the open. The
 * group is the directory's — the consumer directory is set-group-ID (R-E1a),
 * and `chown(2)` would refuse the vault user any group it is not in. On
 * win32 the mode is advisory and no `icacls` runs: the temporary inherits the
 * consumer directory's ACEs (the daemon, SYSTEM and Administrators full, the
 * consumer read and execute — measured), and the rename keeps them.
 */
function openTokenFile(path: string): PendingTokenFile {
  const tmp = join(dirname(path), `${basename(path)}.${randomBytes(6).toString("hex")}.tmp`);
  let fd: number;
  try {
    fd = openSync(tmp, "wx", TOKEN_FILE_MODE);
  } catch (err) {
    throw tokenFileError(path, err);
  }
  try {
    if (process.platform !== "win32") fchmodSync(fd, TOKEN_FILE_MODE);
  } catch (err) {
    closeQuietly(fd);
    unlinkQuietly(tmp);
    throw tokenFileError(path, err);
  }
  let open = true;
  return {
    commit(token: string): void {
      const bytes = Buffer.from(`${token}\n`, "utf8");
      try {
        let offset = 0;
        while (offset < bytes.length) {
          offset += writeSync(fd, bytes, offset, bytes.length - offset);
        }
        fsyncSync(fd);
        open = false;
        closeSync(fd);
        renameOver(tmp, path);
      } catch (err) {
        if (open) closeQuietly(fd);
        open = false;
        unlinkQuietly(tmp);
        throw tokenFileError(path, err);
      } finally {
        bytes.fill(0);
      }
    },
    discard(): void {
      if (open) closeQuietly(fd);
      open = false;
      unlinkQuietly(tmp);
    },
  };
}

/**
 * Replace `path` with `<token>\n` — the bytes `auth token --out` writes and
 * `readLaunchTokenFile` trims — through a temporary and `rename(2)`: a reader
 * opening the path sees the old token or the new one, whole (POSIX; on win32
 * a rename over a file another handle holds open fails `EPERM` and is retried
 * for about half a second, then the write is refused and the old file stays).
 * A failure removes the temporary and throws `FILE_IO_ERROR` naming the path.
 */
export function writeTokenFile(path: string, token: string): void {
  openTokenFile(path).commit(token);
}
