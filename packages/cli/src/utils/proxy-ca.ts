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
import { basename, dirname, join } from "node:path";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { ProxyCaMaterial } from "@harpoc/core";

/** The trust anchor's name in a consumer directory, beside `token.jwt` (DB-14). */
export const CONSUMER_CA_FILE = "ca.pem";

/**
 * `<consumer>/ca.pem`'s mode: the token file's — the daemon writes, the consumer's group reads;
 * the set-group-ID consumer directory gives the group, and on win32 the file inherits the
 * directory's access list (no `icacls`, as `token.jwt`).
 */
export const CONSUMER_CA_FILE_MODE = 0o640;

/** `proxy ca export --out`'s mode: the root certificate is public, its reader any consumer. */
export const EXPORTED_CA_FILE_MODE = 0o644;

/**
 * win32: a rename over a file another handle holds open fails `EPERM` (the token writer's
 * measurement, `core/src/access/token-rotation.ts`) — retried this often, this far apart.
 */
const WIN32_RENAME_ATTEMPTS = 20;
const WIN32_RENAME_RETRY_MS = 25;
const WIN32_RENAME_RETRIED = new Set(["EPERM", "EBUSY", "EACCES"]);

/** The stored CA's `notAfter` as `VaultError.proxyCaExpired` states it (core's one `CERT_EXPIRED`). */
const EXPIRED_AT = / expired at ([^\s;]+);/;

/**
 * The Harpoc CA as `server start --proxy` uses it: `options` is what `createEgressProxy` takes
 * (the intermediate, its key's PEM bytes — zero-filled by the daemon once the proxy is created —
 * and the host list that bounds CONNECT in both modes, RD-B8-13); the root is written into the
 * consumer directories; the rest names the CA in the startup line.
 */
export interface ProxyCaWiring {
  options: { certPem: string; keyPem: Buffer; hosts: string[] };
  rootPem: string;
  unconstrained: boolean;
  notAfter: number;
  fingerprint256: string;
}

/**
 * The engine's one load, shaped for the daemon; undefined when the vault holds no CA, and when
 * it holds an expired one (R-C6): the line on stderr, the daemon started without CONNECT.
 */
export async function loadProxyCaWiring(engine: {
  loadProxyCa(): Promise<ProxyCaMaterial | null>;
}): Promise<ProxyCaWiring | undefined> {
  let material: ProxyCaMaterial | null;
  try {
    material = await engine.loadProxyCa();
  } catch (err) {
    if (!(err instanceof VaultError) || err.code !== ErrorCode.CERT_EXPIRED) throw err;
    const expiredAt = EXPIRED_AT.exec(err.message)?.[1] ?? "<unknown>";
    console.error(
      `[harpoc] Harpoc CA expired at ${expiredAt} — CONNECT disabled until harpoc proxy ca init --force`,
    );
    return undefined;
  }
  if (material === null) return undefined;
  return {
    options: { certPem: material.certPem, keyPem: material.keyPem, hosts: material.hosts },
    rootPem: material.rootPem,
    unconstrained: material.unconstrained,
    notAfter: material.notAfter,
    fingerprint256: material.fingerprint256,
  };
}

/** The first eight octets of a SHA-256 fingerprint — the startup line's short form. */
export function fingerprintPrefix(fingerprint256: string): string {
  return `${fingerprint256.split(":").slice(0, 8).join(":")}…`;
}

/**
 * The startup line's CONNECT clause: ` — CONNECT for <n> host(s)` (the form lane T's rows match)
 * and the CA's short fingerprint; the fallback says its certificates are unconstrained and when
 * they expire.
 */
export function connectSummary(ca: ProxyCaWiring): string {
  const head = ` — CONNECT for ${String(ca.options.hosts.length)} host(s)`;
  const fingerprint = fingerprintPrefix(ca.fingerprint256);
  return ca.unconstrained
    ? `${head}, certificates unconstrained (Harpoc CA SHA-256 ${fingerprint}, until ${new Date(ca.notAfter).toISOString()})`
    : `${head} (Harpoc CA SHA-256 ${fingerprint})`;
}

/** A synchronous pause between win32 rename attempts. */
function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function renameOver(tmp: string, path: string): void {
  for (let attempt = 1; ; attempt += 1) {
    try {
      renameSync(tmp, path);
      return;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (
        process.platform !== "win32" ||
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

function caFileError(path: string, err: unknown): VaultError {
  const code = err instanceof Error ? (err as NodeJS.ErrnoException).code : undefined;
  return new VaultError(
    ErrorCode.FILE_IO_ERROR,
    `could not write the CA certificate ${path} (${code ?? "unknown error"})`,
  );
}

/**
 * Replace `path` with the PEM through a temporary `<file>.<12 hex>.tmp` beside it — `wx` at
 * `mode`, on POSIX `fchmod(mode)` before any byte (the umask may have narrowed the open),
 * `fsync`ed and `rename`d over the file — so a reader sees the old certificate or the new one,
 * whole. The token writer's shape (`core/src/access/token-rotation.ts`). A failure removes the
 * temporary and throws `FILE_IO_ERROR` naming the path and the errno code.
 */
export function writeCaFile(path: string, pem: string, mode: number): void {
  const tmp = join(dirname(path), `${basename(path)}.${randomBytes(6).toString("hex")}.tmp`);
  let fd: number;
  try {
    fd = openSync(tmp, "wx", mode);
  } catch (err) {
    throw caFileError(path, err);
  }
  let open = true;
  try {
    if (process.platform !== "win32") fchmodSync(fd, mode);
    const bytes = Buffer.from(pem, "utf8");
    let offset = 0;
    while (offset < bytes.length) offset += writeSync(fd, bytes, offset, bytes.length - offset);
    fsyncSync(fd);
    open = false;
    closeSync(fd);
    renameOver(tmp, path);
  } catch (err) {
    if (open) {
      try {
        closeSync(fd);
      } catch {
        // The thrown error names the file.
      }
    }
    try {
      unlinkSync(tmp);
    } catch {
      // Best effort: the thrown error names the file.
    }
    throw caFileError(path, err);
  }
}

/**
 * The root as `<dir>/ca.pem` in every consumer directory, in order, at `CONSUMER_CA_FILE_MODE` —
 * the first failure throws, before any listener's `server.start` row (fail closed). Returns the
 * paths written.
 */
export function writeConsumerCaFiles(dirs: readonly string[], rootPem: string): string[] {
  return dirs.map((dir) => {
    const path = join(dir, CONSUMER_CA_FILE);
    writeCaFile(path, rootPem, CONSUMER_CA_FILE_MODE);
    return path;
  });
}
