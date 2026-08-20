import { isIP } from "node:net";
import type { DbCommandAdapter, DbConnectOptions, DbQueryResult } from "./db-adapters.js";
import { identityCheckerFor } from "./db-adapters.js";

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
 *    (verified against `MongoClientOptions` in the installed mongodb@7.5.0's
 *    `mongodb.d.ts`) forces a single, non-discovering topology: the driver
 *    dials exactly the one seed given below and nothing else. This is
 *    mandatory, not optional — the pinned address alone does not close this
 *    hole, only `directConnection` does.
 *
 * 2. Dial-target pinning. The connection URI's host is the SSRF-validated
 *    `opts.address` (always an IP literal — never `opts.host` — closing the
 *    validate-then-reconnect DNS-rebinding TOCTOU window the pg/redis
 *    adapters close via a pinned socket/dial). TLS identity is bound to the
 *    *logical* `opts.host` regardless: verified against mongodb@7.5.0's
 *    compiled `lib/cmap/connect.js`, `LEGAL_TLS_SOCKET_OPTIONS` (`ca`,
 *    `cert`, `checkServerIdentity`, `rejectUnauthorized`, `servername`, ...)
 *    is spread directly onto the object passed to `node:tls.connect()` with
 *    no field remapping — the same wire shape RedisAdapter documents for
 *    node-redis. That means:
 *      - `servername` must be supplied BY US whenever `opts.host` is a real
 *        hostname (`pinned` below): the driver's own default-servername
 *        logic (`parseSslOptions`, "set default sni servername to be the
 *        same as host") only fires when `!net.isIP(result.host)`, and
 *        `result.host` here is always `opts.address` — an IP literal — so
 *        the driver's auto-default never engages and would otherwise send no
 *        SNI name at all.
 *      - `checkServerIdentity` must be bound to `opts.host` explicitly
 *        (`identityCheckerFor`, shared with Postgres/Redis) rather than left
 *        to Node's own derivation (`servername || host || "localhost"`),
 *        which — dialing an IP with no servername in the unpinned
 *        (`opts.host` itself an IP) case — would check the wrong name.
 *
 * Command-phase timeout (Task 10 carry-forward: `connectTimeoutMS`/
 * `serverSelectionTimeoutMS` bound only the connect handshake, not a
 * long-running command). mongodb@7.5.0's CSOT (`timeoutMS` — the documented
 * replacement for the legacy per-phase timeout options) is passed as a
 * *per-call* option to `db.command()`, verified end-to-end against the
 * compiled driver:
 *   - `db.js`'s `Db.command()` forwards `options.timeoutMS` into a
 *     `RunCommandOperation`; `execute_operation.js` sees a numeric
 *     `timeoutMS` and builds a `CSOTTimeoutContext` for that one operation
 *     (`timeout.js`'s `isCSOTTimeoutContextOptions`) — CSOT does not need to
 *     be enabled client-wide.
 *   - `cmap/connection.js`'s `sendWire` calls
 *     `timeoutContext.addMaxTimeMSToCommand(cmd, options)` for every
 *     outgoing command; `RunCommandOperation.buildCommand` returns the
 *     caller's document unmutated beforehand, so this CSOT injection is the
 *     ONLY thing that adds a bound to a `db.command()` call — `Db.command`'s
 *     `RunCommandOptions` has no public `maxTimeMS` field in this driver
 *     version, only `timeoutMS`. The injected `command.maxTimeMS` tells the
 *     SERVER to abort the command after that many ms.
 *   - `cmap/on_data.js`'s `onData` additionally races the socket read
 *     against `timeoutContext.timeoutForSocketRead`
 *     (`CSOTTimeoutContext.timeoutForSocketRead`, `timeout.js`) — a
 *     CLIENT-side deadline that rejects the pending read once the same
 *     budget elapses even if the server never responds at all (network
 *     partition, or a server that ignores `maxTimeMS`). This is the backstop
 *     an unbounded `$where` loop or a non-cooperative server needs so
 *     `finally`/`client.close()` below is always reached.
 * `socketTimeoutMS` is set alongside as a connection-level idle-read bound
 * for phases CSOT does not cover (the initial handshake, before any
 * operation-scoped `timeoutContext` exists) — defense in depth, mirroring
 * `RedisAdapter`'s `connectTimeout`/`socketTimeout` pair.
 */
export class MongoAdapter implements DbCommandAdapter {
  async execute(opts: DbConnectOptions, command: unknown): Promise<DbQueryResult> {
    const { MongoClient } = await import("mongodb");

    // SNI (and the driver's own servername auto-default) forbids an
    // IP-literal servername — only supply one when `opts.host` is a hostname
    // that was actually pinned to a different dial address.
    const pinned = opts.address !== opts.host;
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
            checkServerIdentity: identityCheckerFor(opts.host),
            ...(pinned ? { servername: opts.host } : {}),
          }),
    });

    await client.connect();
    try {
      const response = await client
        .db(opts.database)
        .command(command as Record<string, unknown>, { timeoutMS: opts.timeoutMs });
      return normalizeMongoResult(response as Record<string, unknown>);
    } finally {
      try {
        await client.close();
      } catch {
        // best-effort close
      }
    }
  }
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
