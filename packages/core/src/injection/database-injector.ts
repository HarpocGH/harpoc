import type { ConnectionConfig, DatabaseAction, DatabaseResult, InjectionPolicy } from "@harpoc/shared";
import {
  DEFAULT_DB_TIMEOUT_MS,
  MAX_DB_RESULT_BYTES,
  MAX_DB_ROWS,
  VaultError,
} from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { matchesHostPortAllowlist } from "./allowlist.js";
import type { DbEngineAdapter, DbTlsOptions } from "./db-adapters.js";
import { defaultDbAdapters, defaultDbPort } from "./db-adapters.js";
import { mapStringLeaves, redactSecretEncodings } from "./output-sanitizer.js";
import { validateHostPort } from "./url-validator.js";

/**
 * Executes a SQL query with an injected credential (request-mediated injection,
 * thesis §4.5.5). The vault assembles the connection in-process — the credential
 * (`username:password`) never appears in the agent's context — connects with TLS
 * and server-certificate verification by default, runs the query and returns the
 * sanitized result set.
 *
 * Security controls realized here:
 *  - Host:port target allowlist (optional layer atop the mandatory SSRF floor).
 *  - SSRF: private/internal targets rejected before any connection; the
 *    connection is pinned to the pre-flight-validated address (DNS rebinding).
 *  - TLS by default; a non-TLS connection requires the audited per-secret opt-out.
 *  - Result + error sanitization: the credential and its encodings are redacted.
 */
export class DatabaseInjector {
  private readonly adapters: Record<string, DbEngineAdapter>;

  constructor(
    private readonly auditLogger: AuditLogger | null,
    adapters?: Record<string, DbEngineAdapter>,
  ) {
    this.adapters = adapters ?? defaultDbAdapters();
  }

  async executeWithSecret(
    action: DatabaseAction,
    secretValue: Uint8Array,
    policy: InjectionPolicy,
    config: ConnectionConfig | undefined,
    secretId?: string,
  ): Promise<DatabaseResult> {
    const adapter = this.adapters[action.engine];
    if (!adapter) {
      this.audit(action, secretId, { error: "UNSUPPORTED_DB_ENGINE" }, false);
      throw VaultError.unsupportedDbEngine(action.engine);
    }

    const { host, port } = parseHostPort(action.host, action.port, defaultDbPort(action.engine));

    // Target allowlist (optional) — reject a redirected host:port before connecting.
    if (!matchesHostPortAllowlist(host, port, policy.host_allowlist)) {
      this.audit(action, secretId, { host, port, error: "HOST_NOT_ALLOWED" }, false);
      throw VaultError.hostNotAllowed(`${host}:${port}`);
    }

    // SSRF: reject private/internal targets (mandatory floor). The connection
    // is then pinned to the address validated here — the driver dials the IP
    // and never re-resolves the hostname, closing the DNS-rebinding TOCTOU
    // window (parity with the HTTP injector's pinned lookup).
    let pinnedAddress: string;
    try {
      const validated = await validateHostPort(host, port);
      pinnedAddress = validated.resolvedAddress;
    } catch (err) {
      if (err instanceof VaultError) {
        this.audit(action, secretId, { host, port, error: err.code }, false);
      }
      throw err;
    }

    // TLS policy: required by default; `disable` is the audited opt-out.
    const dbConfig = config?.database;
    const tlsMode = dbConfig?.tls_mode ?? "require";
    const tls: DbTlsOptions = tlsMode === "disable" ? false : { ca: dbConfig?.ca_pem };

    const { user, password } = parseUserPassword(secretValue);
    const timeoutMs = action.timeout_ms ?? DEFAULT_DB_TIMEOUT_MS;

    // The username half of the credential is redacted alongside the password;
    // a 1–2 char username would shred unrelated output, so it stays unredacted.
    const redactCredential = (s: string): string => {
      const redacted = redactSecretEncodings(s, password);
      return user.length >= 3 ? redactSecretEncodings(redacted, user) : redacted;
    };

    let connection;
    try {
      connection = await adapter.connect({
        host,
        port,
        address: pinnedAddress,
        user,
        password,
        database: action.database,
        tls,
        timeoutMs,
      });
    } catch (err) {
      const detail = redactCredential(errMessage(err));
      this.audit(action, secretId, { host, port, error: "DB_CONNECTION_FAILED" }, false);
      throw VaultError.dbConnectionFailed(detail);
    }

    try {
      const res = await connection.query(action.query, action.params);
      const { rows, truncated } = capRows(res.rows);
      const result: DatabaseResult = {
        type: "database",
        row_count: res.rowCount ?? rows.length,
        rows: mapStringLeaves(rows, redactCredential) as unknown[],
        fields: res.fields,
        command: res.command,
        truncated: truncated ? true : undefined,
      };
      this.audit(
        action,
        secretId,
        { host, port, row_count: result.row_count, truncated: truncated ? true : false },
        true,
      );
      return result;
    } catch (err) {
      const detail = redactCredential(errMessage(err));
      this.audit(action, secretId, { host, port, error: "DB_QUERY_FAILED" }, false);
      throw VaultError.dbQueryFailed(detail);
    } finally {
      try {
        await connection.end();
      } catch {
        // best-effort close
      }
    }
  }

  private audit(
    action: DatabaseAction,
    secretId: string | undefined,
    detail: Record<string, unknown>,
    success: boolean,
  ): void {
    this.auditLogger?.log({
      eventType: "secret.use",
      secretId,
      detail: { context: "database", engine: action.engine, database: action.database, ...detail },
      success,
    });
  }
}

/** Split `host` (which may embed `:port`) and an optional explicit port. */
function parseHostPort(
  hostField: string,
  portField: number | undefined,
  fallback: number,
): { host: string; port: number } {
  const m = /^(.*):(\d+)$/.exec(hostField);
  if (m && m[1] !== undefined && m[2] !== undefined) {
    const embedded = parseInt(m[2], 10);
    if (embedded < 1 || embedded > 65_535) {
      throw VaultError.invalidDatabaseConfig("embedded port out of range (1-65535)");
    }
    return { host: m[1], port: portField ?? embedded };
  }
  return { host: hostField, port: portField ?? fallback };
}

/** Split the secret value into username and password on the first colon. */
function parseUserPassword(value: Uint8Array): { user: string; password: string } {
  const s = Buffer.from(value).toString("utf8");
  const i = s.indexOf(":");
  if (i < 0) {
    throw VaultError.invalidDatabaseConfig("database secret must be in 'username:password' form");
  }
  return { user: s.slice(0, i), password: s.slice(i + 1) };
}

/** Cap the result set by row count and serialized size. */
function capRows(rows: unknown[]): { rows: unknown[]; truncated: boolean } {
  let capped = rows;
  let truncated = false;
  if (capped.length > MAX_DB_ROWS) {
    capped = capped.slice(0, MAX_DB_ROWS);
    truncated = true;
  }
  while (capped.length > 0 && Buffer.byteLength(JSON.stringify(capped), "utf8") > MAX_DB_RESULT_BYTES) {
    capped = capped.slice(0, Math.ceil(capped.length / 2));
    truncated = true;
  }
  return { rows: capped, truncated };
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : "unknown error";
}
