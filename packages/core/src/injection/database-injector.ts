import type {
  ConnectionConfig,
  DatabaseAction,
  DatabaseResult,
  InjectionPolicy,
  VaultText,
} from "@harpoc/shared";
import {
  databaseActionSchema,
  DatabaseEngine,
  DEFAULT_DB_TIMEOUT_MS,
  echoField,
  ErrorCode,
  isDecimalInteger,
  MAX_DB_RESULT_BYTES,
  MAX_DB_ROWS,
  MIN_REDACTABLE_FRAGMENT,
  num,
  VaultError,
  vaultText,
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
import { passError } from "./error-pass.js";
import { mapStringLeavesTracked, outside, redactValues } from "./output-sanitizer.js";
import { validateHostPort } from "./url-validator.js";

/** The adapter an action dispatches through, tagged so each arm narrows without a cast. */
type ResolvedAdapter =
  { kind: "command"; adapter: DbCommandAdapter } | { kind: "sql"; adapter: DbEngineAdapter };

/**
 * Executes a SQL query with an injected credential (request-mediated injection,
 * thesis §4.5.5). The vault assembles the connection in-process — the credential
 * (`username:password`) never appears in the agent's context — connects with TLS
 * and server-certificate verification by default, runs the query and returns the
 * sanitized result set.
 *
 * Security controls realized here:
 *  - Host:port target allowlist (deny-by-default, atop the mandatory SSRF floor).
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
    const engine: unknown = action.engine;
    if (typeof engine === "string") {
      if (isCommandEngine(engine)) {
        const adapter = ownEntry(this.commandAdapters, engine);
        if (adapter) return { kind: "command", adapter };
      } else {
        const adapter = ownEntry(this.adapters, engine);
        if (adapter) return { kind: "sql", adapter };
      }
    }
    this.audit(action, secretId, { error: "UNSUPPORTED_DB_ENGINE" }, false, attribution);
    throw VaultError.unsupportedDbEngine(
      typeof engine === "string" ? echoField(action, "engine") : vaultText`(not a string)`,
    );
  }

  async executeWithSecret(
    action: DatabaseAction,
    secretValue: Uint8Array,
    policy: InjectionPolicy,
    config: ConnectionConfig | undefined,
    secretId?: string,
    attribution?: AuditAttribution,
    signal?: AbortSignal,
  ): Promise<DatabaseResult> {
    const valueStr = Buffer.from(secretValue).toString("utf8");
    const splitValues = credentialParts(valueStr);
    const thrownValues = [valueStr, ...splitValues];
    try {
      const resolved = this.resolveAdapter(action, secretId, attribution);

      let target: { host: string; port: number; embedsPort: boolean };
      try {
        const refusal = databaseInputRefusal(action);
        if (refusal !== undefined) throw VaultError.invalidDatabaseConfig(refusal);
        const hostField: unknown = action.host;
        if (typeof hostField !== "string") {
          throw VaultError.invalidDatabaseConfig(vaultText`host must be a string`);
        }
        target = parseHostPort(hostField, action.port, defaultDbPort(action.engine));
      } catch (err) {
        if (err instanceof VaultError) {
          this.audit(action, secretId, { error: err.code }, false, attribution);
        }
        throw err;
      }
      const { host, port } = target;

      // Target allowlist — deny-by-default; an unlisted or redirected host:port is refused before connecting.
      if (!matchesHostPortAllowlist(host, port, policy.host_allowlist)) {
        this.audit(action, secretId, { host, port, error: "HOST_NOT_ALLOWED" }, false, attribution);
        throw VaultError.hostNotAllowed(targetText(action, target.embedsPort, port));
      }

      // SSRF: reject private/internal targets (mandatory floor). The connection
      // is then pinned to the address validated here — the driver dials the IP
      // and never re-resolves the hostname, closing the DNS-rebinding TOCTOU
      // window (parity with the HTTP injector's pinned lookup).
      let pinnedAddress: string;
      try {
        const validated = await validateHostPort(host, port, {
          parts: echoField(action, "host"),
          values: thrownValues,
        });
        if (signal?.aborted) throw VaultError.vaultLocked();
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

      let credential: { user: string; password: string };
      try {
        credential = parseUserPassword(secretValue);
      } catch (err) {
        if (err instanceof VaultError) {
          this.audit(
            action,
            secretId,
            { host, port, error: err.code, ...tlsOptOut },
            false,
            attribution,
          );
        }
        throw err;
      }
      const { user, password } = credential;
      const timeoutMs = action.timeout_ms ?? DEFAULT_DB_TIMEOUT_MS;
      const redactCredential = (s: string): string => redactValues(s, splitValues);

      const connectOpts = {
        host,
        servername: dbConfig?.servername,
        port,
        address: pinnedAddress,
        user,
        password,
        database: action.database,
        tls,
        timeoutMs,
        ...(signal === undefined ? {} : { signal }),
      };

      if (resolved.kind === "command") {
        // Command-style engines (redis, mongodb) have no separate connect/query
        // split — `execute` owns its own connection lifecycle end to end — so a
        // failure anywhere inside it (connect or command) surfaces as one
        // DB_QUERY_FAILED, the same code an equivalent SQL query error maps to;
        // a VAULT_LOCKED keeps its own code.
        try {
          const res = await resolved.adapter.execute(connectOpts, action.command);
          const { result, truncated, sanitized } = this.toDatabaseResult(res, redactCredential);
          this.audit(
            action,
            secretId,
            {
              host,
              port,
              row_count: result.row_count,
              truncated,
              ...tlsOptOut,
              ...(sanitized ? { sanitized: true } : {}),
            },
            true,
            attribution,
          );
          return result;
        } catch (err) {
          if (err instanceof VaultError && err.code === ErrorCode.VAULT_LOCKED) {
            this.audit(
              action,
              secretId,
              { host, port, error: err.code, ...tlsOptOut },
              false,
              attribution,
            );
            throw err;
          }
          const detail = outside(errMessage(err), thrownValues);
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
        if (err instanceof VaultError && err.code === ErrorCode.VAULT_LOCKED) {
          this.audit(
            action,
            secretId,
            { host, port, error: err.code, ...tlsOptOut },
            false,
            attribution,
          );
          throw err;
        }
        const detail = outside(errMessage(err), thrownValues);
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
        const { result, truncated, sanitized } = this.toDatabaseResult(res, redactCredential);
        this.audit(
          action,
          secretId,
          {
            host,
            port,
            row_count: result.row_count,
            truncated,
            ...tlsOptOut,
            ...(sanitized ? { sanitized: true } : {}),
          },
          true,
          attribution,
        );
        return result;
      } catch (err) {
        const detail = outside(errMessage(err), thrownValues);
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
    } catch (err) {
      throw passError(err, thrownValues);
    }
  }

  /** Cap + redact a driver result into the wire `DatabaseResult` shape shared by
   * both dispatch paths. `sanitized` reports whether the redaction changed
   * anything anywhere in the projection — rows, column names or command tag. */
  private toDatabaseResult(
    res: DbQueryResult,
    redactCredential: (s: string) => string,
  ): { result: DatabaseResult; truncated: boolean; sanitized: boolean } {
    const { rows, truncated } = capRows(res.rows);
    const walked = mapStringLeavesTracked(rows, redactCredential, 0);
    const fields = res.fields.map((f) => ({ name: redactCredential(f.name) }));
    const command = res.command === undefined ? undefined : redactCredential(res.command);
    const sanitized =
      walked.changed ||
      fields.some((f, i) => f.name !== res.fields[i]?.name) ||
      (command !== undefined && command !== res.command);
    const result: DatabaseResult = {
      type: "database",
      row_count: res.rowCount ?? rows.length,
      rows: walked.value as unknown[],
      fields,
      command,
      truncated: truncated ? true : undefined,
    };
    return { result, truncated, sanitized };
  }

  private audit(
    action: DatabaseAction,
    secretId: string | undefined,
    detail: Record<string, unknown>,
    success: boolean,
    attribution?: AuditAttribution,
  ): void {
    const engine: unknown = action.engine;
    this.auditLogger?.log(
      withAttribution(
        {
          eventType: "secret.use",
          secretId,
          detail: {
            context: "database",
            ...(typeof engine === "string" ? { engine } : {}),
            ...(FIELD.database.safeParse(action.database).success
              ? { database: action.database }
              : {}),
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
const COMMAND_ENGINES: readonly string[] = [DatabaseEngine.REDIS, DatabaseEngine.MONGODB];

function isCommandEngine(engine: string): engine is DbCommandEngine {
  return COMMAND_ENGINES.includes(engine);
}

function ownEntry<T>(table: Partial<Record<string, T>>, key: string): T | undefined {
  return Object.hasOwn(table, key) ? table[key] : undefined;
}

function isDocument(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

const FIELD = databaseActionSchema.shape;

function databaseInputRefusal(action: DatabaseAction): VaultText | undefined {
  const sql = action.engine === DatabaseEngine.POSTGRESQL || action.engine === DatabaseEngine.MYSQL;
  if (action.engine === DatabaseEngine.MONGODB && !isDocument(action.command)) {
    return vaultText`command must be a document for mongodb`;
  }
  if (action.engine === DatabaseEngine.REDIS && !isStringArray(action.command)) {
    return vaultText`command must be a string array for redis`;
  }
  if (sql && (typeof action.query !== "string" || action.query.length === 0)) {
    return vaultText`query is required for this engine`;
  }
  if (sql && !FIELD.params.safeParse(action.params).success) {
    return vaultText`params must be an array of at most 1000 values`;
  }
  if (!FIELD.database.safeParse(action.database).success) return vaultText`Invalid database name`;
  if (action.engine === DatabaseEngine.REDIS && !isDecimalInteger(action.database)) {
    return vaultText`database must be a non-negative integer index for redis`;
  }
  if (!FIELD.timeout_ms.safeParse(action.timeout_ms).success) {
    return vaultText`timeout_ms must be a positive integer up to 300000`;
  }
  return undefined;
}

function isStringArray(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.findIndex((entry) => typeof entry !== "string") === -1
  );
}

/** Split `host` (which may embed `:port`) and an optional explicit port. */
function parseHostPort(
  hostField: string,
  portField: number | undefined,
  fallback: number,
): { host: string; port: number; embedsPort: boolean } {
  const m = /^(.*):(\d+)$/.exec(hostField);
  if (m && m[1] !== undefined && m[2] !== undefined) {
    const embedded = parseInt(m[2], 10);
    if (embedded < 1 || embedded > 65_535) {
      throw VaultError.invalidDatabaseConfig(vaultText`embedded port out of range (1-65535)`);
    }
    return { host: m[1], port: portField ?? embedded, embedsPort: true };
  }
  return { host: hostField, port: portField ?? fallback, embedsPort: false };
}

/** The target as the action named it: the host field as sent, and the port unless the field embeds one and the action sent none. */
function targetText(action: DatabaseAction, embedsPort: boolean, port: number): VaultText {
  const sent: unknown = action.port;
  const host = echoField(action, "host");
  if (embedsPort && (sent === undefined || sent === null)) return vaultText`${host}`;
  return vaultText`${host}:${typeof sent === "string" ? echoField(action, "port") : num(port)}`;
}

/** Split the secret value into username and password on the first colon. */
function parseUserPassword(value: Uint8Array): { user: string; password: string } {
  const s = Buffer.from(value).toString("utf8");
  const i = s.indexOf(":");
  if (i < 0) {
    throw VaultError.invalidDatabaseConfig(
      vaultText`database secret must be in 'username:password' form`,
    );
  }
  return { user: s.slice(0, i), password: s.slice(i + 1) };
}

/** The parts a `username:password` value is redacted of beside the whole: the password, and the user down to the shared floor (MIN_REDACTABLE_FRAGMENT). */
function credentialParts(value: string): string[] {
  const i = value.indexOf(":");
  if (i < 0) return [];
  const user = value.slice(0, i);
  const password = value.slice(i + 1);
  return user.length >= MIN_REDACTABLE_FRAGMENT ? [password, user] : [password];
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
