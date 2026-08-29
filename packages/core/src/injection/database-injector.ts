import type {
  ConnectionConfig,
  DatabaseAction,
  DatabaseResult,
  InjectionPolicy,
} from "@harpoc/shared";
import {
  DatabaseEngine,
  DEFAULT_DB_TIMEOUT_MS,
  MAX_DB_RESULT_BYTES,
  MAX_DB_ROWS,
  MIN_REDACTABLE_FRAGMENT,
  VaultError,
} from "@harpoc/shared";
import type { AuditAttribution } from "../audit/attribution.js";
import { withAttribution } from "../audit/attribution.js";
import type { AuditLogger } from "../audit/audit-logger.js";
import { matchesHostPortAllowlist } from "./allowlist.js";
import type {
  DbCommandAdapter,
  DbCommandEngine,
  DbEngineAdapter,
  DbQueryResult,
  DbSqlEngine,
  DbTlsOptions,
} from "./db-adapters.js";
import { defaultDbAdapters, defaultDbCommandAdapters, defaultDbPort } from "./db-adapters.js";
import { mapStringLeaves, redactSecretEncodings } from "./output-sanitizer.js";
import { validateHostPort } from "./url-validator.js";

/** The adapter an action dispatches through, tagged so each arm narrows without a cast. */
type ResolvedAdapter =
  | { kind: "command"; adapter: DbCommandAdapter }
  | { kind: "sql"; adapter: DbEngineAdapter };

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
  private readonly adapters: Partial<Record<DbSqlEngine, DbEngineAdapter>>;
  private readonly commandAdapters: Partial<Record<DbCommandEngine, DbCommandAdapter>>;

  constructor(
    private readonly auditLogger: AuditLogger | null,
    adapters?: Partial<Record<DbSqlEngine, DbEngineAdapter>>,
    commandAdapters?: Partial<Record<DbCommandEngine, DbCommandAdapter>>,
  ) {
    this.adapters = adapters ?? defaultDbAdapters();
    this.commandAdapters = commandAdapters ?? defaultDbCommandAdapters();
  }

  /**
   * Resolves the action's adapter ahead of every pre-connect step, so an
   * unsupported engine is refused — and its audit row written — before the
   * host is parsed, allowlisted or resolved: the refusal row carries no
   * `host`/`port` and is always the first row the action writes.
   */
  private resolveAdapter(
    action: DatabaseAction,
    secretId: string | undefined,
    attribution: AuditAttribution | undefined,
  ): ResolvedAdapter {
    if (isCommandEngine(action.engine)) {
      const adapter = this.commandAdapters[action.engine];
      if (adapter) return { kind: "command", adapter };
    } else {
      const adapter = this.adapters[action.engine];
      if (adapter) return { kind: "sql", adapter };
    }
    this.audit(action, secretId, { error: "UNSUPPORTED_DB_ENGINE" }, false, attribution);
    throw VaultError.unsupportedDbEngine(action.engine);
  }

  async executeWithSecret(
    action: DatabaseAction,
    secretValue: Uint8Array,
    policy: InjectionPolicy,
    config: ConnectionConfig | undefined,
    secretId?: string,
    attribution?: AuditAttribution,
  ): Promise<DatabaseResult> {
    const resolved = this.resolveAdapter(action, secretId, attribution);

    const { host, port } = parseHostPort(action.host, action.port, defaultDbPort(action.engine));

    // Target allowlist (optional) — reject a redirected host:port before connecting.
    if (!matchesHostPortAllowlist(host, port, policy.host_allowlist)) {
      this.audit(action, secretId, { host, port, error: "HOST_NOT_ALLOWED" }, false, attribution);
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
        this.audit(action, secretId, { host, port, error: err.code }, false, attribution);
      }
      throw err;
    }

    // TLS policy: required by default; `disable` is the audited opt-out.
    const dbConfig = config?.database;
    const tlsMode = dbConfig?.tls_mode ?? "require";
    const tls: DbTlsOptions = tlsMode === "disable" ? false : { ca: dbConfig?.ca_pem };
    // The opt-out is stamped on every row written past this point: the config
    // records the operator's choice, the use row records that the credential
    // actually crossed a plaintext leg. The pre-connect refusals above are
    // deliberately excluded — they resolve no connection config (D13).
    const tlsOptOut = tlsMode === "disable" ? { tls_opt_out: true } : {};

    const { user, password } = parseUserPassword(secretValue);
    const timeoutMs = action.timeout_ms ?? DEFAULT_DB_TIMEOUT_MS;

    // The username half of the credential is redacted alongside the password,
    // down to the shared floor (MIN_REDACTABLE_FRAGMENT).
    const redactCredential = (s: string): string => {
      const redacted = redactSecretEncodings(s, password);
      return user.length >= MIN_REDACTABLE_FRAGMENT
        ? redactSecretEncodings(redacted, user)
        : redacted;
    };

    const connectOpts = {
      host,
      port,
      address: pinnedAddress,
      user,
      password,
      database: action.database,
      tls,
      timeoutMs,
    };

    if (resolved.kind === "command") {
      // Command-style engines (redis, mongodb) have no separate connect/query
      // split — `execute` owns its own connection lifecycle end to end — so a
      // failure anywhere inside it (connect or command) surfaces as one
      // DB_QUERY_FAILED, the same code an equivalent SQL query error maps to.
      try {
        const res = await resolved.adapter.execute(connectOpts, action.command);
        const { result, truncated } = this.toDatabaseResult(res, redactCredential);
        this.audit(
          action,
          secretId,
          { host, port, row_count: result.row_count, truncated, ...tlsOptOut },
          true,
          attribution,
        );
        return result;
      } catch (err) {
        const detail = redactCredential(errMessage(err));
        this.audit(
          action,
          secretId,
          { host, port, error: "DB_QUERY_FAILED", ...tlsOptOut },
          false,
          attribution,
        );
        throw VaultError.dbQueryFailed(detail);
      }
    }

    // Narrowed by the command arm above, which returns or throws on every path.
    const sqlAdapter = resolved.adapter;
    let connection;
    try {
      connection = await sqlAdapter.connect(connectOpts);
    } catch (err) {
      const detail = redactCredential(errMessage(err));
      this.audit(
        action,
        secretId,
        { host, port, error: "DB_CONNECTION_FAILED", ...tlsOptOut },
        false,
        attribution,
      );
      throw VaultError.dbConnectionFailed(detail);
    }

    try {
      // The schema's superRefine guarantees `query` for every SQL engine.
      const query = action.query as string;
      const res = await connection.query(query, action.params);
      // Column names and the command tag are endpoint-authored too: an alias
      // (`SELECT 1 AS "<credential>"`) put the value in a position no redactor
      // saw, while the same string in a row value was redacted (L1).
      const { result, truncated } = this.toDatabaseResult(res, redactCredential);
      this.audit(
        action,
        secretId,
        { host, port, row_count: result.row_count, truncated, ...tlsOptOut },
        true,
        attribution,
      );
      return result;
    } catch (err) {
      const detail = redactCredential(errMessage(err));
      this.audit(
        action,
        secretId,
        { host, port, error: "DB_QUERY_FAILED", ...tlsOptOut },
        false,
        attribution,
      );
      throw VaultError.dbQueryFailed(detail);
    } finally {
      try {
        await connection.end();
      } catch {
        // best-effort close
      }
    }
  }

  /** Cap + redact a driver result into the wire `DatabaseResult` shape shared by both dispatch paths. */
  private toDatabaseResult(
    res: DbQueryResult,
    redactCredential: (s: string) => string,
  ): { result: DatabaseResult; truncated: boolean } {
    const { rows, truncated } = capRows(res.rows);
    const result: DatabaseResult = {
      type: "database",
      row_count: res.rowCount ?? rows.length,
      rows: mapStringLeaves(rows, redactCredential) as unknown[],
      fields: res.fields.map((f) => ({ name: redactCredential(f.name) })),
      command: res.command === undefined ? undefined : redactCredential(res.command),
      truncated: truncated ? true : undefined,
    };
    return { result, truncated };
  }

  private audit(
    action: DatabaseAction,
    secretId: string | undefined,
    detail: Record<string, unknown>,
    success: boolean,
    attribution?: AuditAttribution,
  ): void {
    this.auditLogger?.log(
      withAttribution(
        {
          eventType: "secret.use",
          secretId,
          detail: {
            context: "database",
            engine: action.engine,
            database: action.database,
            ...detail,
          },
          success,
        },
        attribution,
      ),
    );
  }
}

/** Command-style engines dispatch through `DbCommandAdapter.execute` instead of `DbEngineAdapter.connect(...).query(...)`. */
const COMMAND_ENGINES: readonly DatabaseEngine[] = [DatabaseEngine.REDIS, DatabaseEngine.MONGODB];

function isCommandEngine(engine: DatabaseEngine): engine is DbCommandEngine {
  return COMMAND_ENGINES.includes(engine);
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
  while (
    capped.length > 0 &&
    Buffer.byteLength(JSON.stringify(capped), "utf8") > MAX_DB_RESULT_BYTES
  ) {
    // Every iteration must strictly shrink the set. `Math.ceil(1/2) === 1` left a
    // single oversized row unchanged and the loop spun forever — synchronously,
    // so one agent-chosen query (`SELECT repeat('x', 2000000)`) hung the whole
    // vault process. A row that cannot fit on its own is dropped instead.
    capped = capped.length === 1 ? [] : capped.slice(0, Math.floor(capped.length / 2));
    truncated = true;
  }
  return { rows: capped, truncated };
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : "unknown error";
}
