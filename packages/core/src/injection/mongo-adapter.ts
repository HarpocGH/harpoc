import { isIP } from "node:net";
import { VaultError } from "@harpoc/shared";
import type { MongoClient } from "mongodb";
import type { DbCommandAdapter, DbConnectOptions, DbQueryResult } from "./db-adapters.js";
import { DB_CLOSE_GRACE_MS, identityCheckerFor } from "./db-adapters.js";

/**
 * Mongo command adapter (request-mediated injection, thesis §4.5.5 extension,
 * v1.3 T11). `mongodb` is lazy-imported so a vault that never runs a mongodb
 * action never loads the driver (mirrors the pg/mysql2/RedisAdapter pattern).
 *
 * SSRF pinning (spec §10.7) — two distinct concerns, both closed here:
 *
 * 1. Server discovery. Unlike the SQL/Redis adapters, the mongodb driver by
 *    default runs full topology discovery (SDAM) on connect: it "hello"s the
 *    seed, learns the replica-set membership the seed *claims* to have, and
 *    opens its own connections to every member advertised — none of which
 *    passes through this vault's SSRF validation. A malicious or compromised
 *    endpoint can advertise arbitrary internal hosts as "replica set peers"
 *    and have the driver dial them unvalidated. `directConnection: true`
 *    (verified against `MongoClientOptions` in the installed mongodb@7.9.0's
 *    `mongodb.d.ts`) forces a single, non-discovering topology: the driver
 *    dials exactly the one seed given below and nothing else. This is
 *    mandatory, not optional — the pinned address alone does not close this
 *    hole, only `directConnection` does.
 *
 * 2. Dial-target pinning. The connection URI's host is the SSRF-validated
 *    `opts.address` (always an IP literal — never `opts.host` — closing the
 *    validate-then-reconnect DNS-rebinding TOCTOU window the pg/redis
 *    adapters close via a pinned socket/dial). TLS identity is bound to
 *    `database.servername` when configured, else to the *logical*
 *    `opts.host`, regardless of the pinned dial: verified against
 *    mongodb@7.9.0's compiled `lib/cmap/connect.js`,
 *    `LEGAL_TLS_SOCKET_OPTIONS` (`ca`, `cert`, `checkServerIdentity`,
 *    `rejectUnauthorized`, `servername`, ...) is copied name by name onto the
 *    object passed to `node:tls.connect()` with no field remapping — the
 *    same wire shape RedisAdapter documents for node-redis. That means:
 *      - `servername` must be supplied BY US — `database.servername` when
 *        configured, else whenever `opts.host` is a real hostname (`pinned`
 *        below): the driver's own default-servername logic
 *        (`parseSslOptions`, "set default sni servername to be the same as
 *        host") only fires when `!net.isIP(result.host)`, and
 *        `result.host` here is always `opts.address` — an IP literal — so
 *        the driver's auto-default never engages and would otherwise send no
 *        SNI name at all.
 *      - `checkServerIdentity` must be bound to `database.servername` when
 *        configured, else to `opts.host`, explicitly
 *        (`identityCheckerFor`, shared with Postgres/Redis) rather than left
 *        to Node's own derivation (`servername || host || "localhost"`),
 *        which — dialing an IP with no servername in the unpinned
 *        (`opts.host` itself an IP) case — would check the wrong name.
 *
 * The budget. `connectTimeoutMS`/`serverSelectionTimeoutMS` do not bound a
 * trickled handshake; mongodb 7.8 made the per-call `timeoutMS` (CSOT) a no-op,
 * so the budget is applied twice, as the pg adapter applies
 * `statement_timeout` and `query_timeout`:
 *   - server side, `maxTimeMS` on a copy of the command document — a caller's
 *     own value is kept only when it is a positive integer below the budget —
 *     so the server aborts the command at the budget (`MaxTimeMSExpired`);
 *   - client side, one deadline at the budget over `connect()` and the command,
 *     armed after `connect()` starts, so a connect failure the driver reports
 *     at its server-selection timer keeps its cause; every other expiry
 *     carries the deadline's reason, a `MongoNetworkError` built first, aborts
 *     the command's `signal` and ends the call whatever the driver does. That
 *     class has the driver mark the server Unknown, so `close()` sends no
 *     `endSessions`; `close()` is raced against `DB_CLOSE_GRACE_MS`.
 * `socketTimeoutMS` stays the connection-level idle-read bound.
 * The SCRAM key derivation is outside every bound above: it runs on a worker
 * thread and cannot be cancelled. The driver is therefore patched
 * (`patches/mongodb@7.9.0.patch`) to refuse an iteration count above 100 000
 * before it derives.
 */
export class MongoAdapter implements DbCommandAdapter {
  async execute(opts: DbConnectOptions, command: unknown): Promise<DbQueryResult> {
    const { MongoClient, MongoNetworkError } = await import("mongodb");
    if (opts.signal?.aborted) throw VaultError.vaultLocked();

    // SNI (and the driver's own servername auto-default) forbids an
    // IP-literal servername — supply `database.servername` when configured,
    // else one only when `opts.host` is a hostname that was actually pinned
    // to a different dial address.
    const pinned = opts.address !== opts.host;
    const servername = opts.servername ?? (pinned ? opts.host : undefined);
    const seedHost = isIP(opts.address) === 6 ? `[${opts.address}]` : opts.address;
    const uri = `mongodb://${seedHost}:${String(opts.port)}/${encodeURIComponent(opts.database)}`;

    const client = new MongoClient(uri, {
      // §10.7 rule 1: forces a single, non-discovering topology — the driver
      // dials exactly this seed and never any peer it claims to have.
      directConnection: true,
      auth: { username: opts.user, password: opts.password },
      connectTimeoutMS: opts.timeoutMs,
      serverSelectionTimeoutMS: opts.timeoutMs,
      socketTimeoutMS: opts.timeoutMs,
      ...(opts.tls === false
        ? { tls: false }
        : {
            tls: true,
            rejectUnauthorized: true,
            tlsAllowInvalidCertificates: false,
            tlsAllowInvalidHostnames: false,
            ca: opts.tls.ca,
            checkServerIdentity: identityCheckerFor(opts.servername ?? opts.host),
            ...(servername === undefined ? {} : { servername }),
          }),
    });

    const abort = new AbortController();
    let deadline: NodeJS.Timeout | undefined;
    try {
      const reason = new MongoNetworkError(
        `command did not complete within ${String(opts.timeoutMs)} ms`,
      );
      const running = run(
        client,
        opts.database,
        withMaxTimeMS(command as Record<string, unknown>, opts.timeoutMs),
        abort.signal,
      );
      const expired = new Promise<never>((_resolve, reject) => {
        deadline = setTimeout(() => {
          abort.abort(reason);
          reject(reason);
        }, opts.timeoutMs);
      });
      const response = await Promise.race([running, expired]);
      return normalizeMongoResult(response as Record<string, unknown>);
    } finally {
      clearTimeout(deadline);
      await closeWithin(client, DB_CLOSE_GRACE_MS);
    }
  }
}

async function run(
  client: MongoClient,
  database: string,
  command: Record<string, unknown>,
  signal: AbortSignal,
): Promise<unknown> {
  await client.connect();
  signal.throwIfAborted();
  return client.db(database).command(command, { signal });
}

async function closeWithin(client: MongoClient, graceMs: number): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  const closing = new Promise<void>((resolve) => {
    resolve(client.close());
  }).catch(() => undefined);
  await Promise.race([
    closing,
    new Promise<void>((resolve) => {
      timer = setTimeout(resolve, graceMs);
    }),
  ]);
  clearTimeout(timer);
}

function withMaxTimeMS(
  command: Record<string, unknown>,
  budgetMs: number,
): Record<string, unknown> {
  const own = command.maxTimeMS;
  const keep = typeof own === "number" && Number.isInteger(own) && own > 0 && own < budgetMs;
  return { ...command, maxTimeMS: keep ? own : budgetMs };
}

/**
 * Normalizes a `db.command()` response per spec §10.7: a cursor-shaped
 * response (`{ cursor: { firstBatch: [...] } }` — e.g. `find`/`aggregate`
 * style commands) unpacks to its batch; any other response document (e.g.
 * `count`, `ping`, `dbStats`) is wrapped as the single row it is.
 */
function normalizeMongoResult(response: Record<string, unknown>): DbQueryResult {
  const cursor = response.cursor;
  if (isCursorShaped(cursor)) {
    const rows = cursor.firstBatch;
    return { rows, fields: fieldsFromRows(rows), rowCount: rows.length };
  }
  return { rows: [response], fields: [{ name: "result" }], rowCount: 1 };
}

function isCursorShaped(value: unknown): value is { firstBatch: unknown[] } {
  return (
    value !== null &&
    typeof value === "object" &&
    Array.isArray((value as { firstBatch?: unknown }).firstBatch)
  );
}

/** Reasonable field names for a batch: the keys of its first document, or a generic fallback. */
function fieldsFromRows(rows: unknown[]): { name: string }[] {
  const first = rows[0];
  if (first !== null && typeof first === "object" && !Array.isArray(first)) {
    const names = Object.keys(first as Record<string, unknown>);
    if (names.length > 0) return names.map((name) => ({ name }));
  }
  return [{ name: "result" }];
}
