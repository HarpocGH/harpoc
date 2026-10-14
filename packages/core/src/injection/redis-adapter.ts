import { isDecimalInteger, VaultError } from "@harpoc/shared";
import type { DbCommandAdapter, DbConnectOptions, DbQueryResult } from "./db-adapters.js";
import { identityCheckerFor } from "./db-adapters.js";

/**
 * Redis command adapter (request-mediated injection, thesis §4.5.5 extension,
 * v1.3 T10). `redis` is lazy-imported so a vault that never runs a redis
 * action never loads the driver (mirrors the pg/mysql2 adapters).
 *
 * SSRF pinning (spec §10.2): node-redis's TLS socket options ARE
 * `tls.ConnectionOptions` verbatim — verified against @redis/client@6.2.1's
 * compiled `socket.js`, which spreads the `socket` option object straight
 * into `node:tls.connect()` with no field remapping. That means the pinning
 * technique mirrors `PostgresAdapter` exactly rather than `MysqlAdapter`'s
 * raw-socket hack: `socket.host` dials the SSRF-validated `opts.address`,
 * `socket.servername` carries `database.servername` when configured, else the
 * *logical* `opts.host`, for SNI (with no override, omitted when the target
 * was not pinned — i.e. `opts.host` is itself an IP literal, since the SNI
 * extension forbids an IP-literal servername), and `checkServerIdentity` is
 * bound to that same name unconditionally via
 * `identityCheckerFor` so certificate-name verification never falls back to
 * Node's own derivation (`servername || host || "localhost"`), which would
 * otherwise check the pinned IP instead of the target the vault validated.
 */
export class RedisAdapter implements DbCommandAdapter {
  async execute(opts: DbConnectOptions, command: unknown): Promise<DbQueryResult> {
    if (!isDecimalInteger(opts.database)) {
      throw VaultError.invalidDatabaseConfig("redis database must be a non-negative integer index");
    }

    const { createClient } = await import("redis");

    // SNI forbids an IP-literal servername; send `database.servername` when
    // configured, else one only when `opts.host` is a hostname that was
    // actually pinned to a different dial address.
    const pinned = opts.address !== opts.host;
    const servername = opts.servername ?? (pinned ? opts.host : undefined);
    // `timeoutMs` is documented (constants.ts) as a connect+query budget —
    // PostgresAdapter mirrors it onto statement_timeout/query_timeout and
    // MysqlAdapter passes it as the per-query `timeout`, each in addition to
    // their connect-phase timeout. `connectTimeout` alone only bounds the
    // handshake: a blocking command (BLPOP key 0, WAIT, XREAD BLOCK 0,
    // SUBSCRIBE, DEBUG SLEEP — the schema allows any string[] command, no
    // denylist) would otherwise hang `sendCommand` forever, and the
    // `finally`/`close()` below would never run. `socketTimeout` closes the
    // socket once the same budget elapses mid-command, which rejects the
    // pending `sendCommand` instead. `reconnectStrategy: false`: this client
    // runs one command and is closed, so a dropped socket has nothing to
    // reconnect for — node-redis's default strategy would retry forever.
    const socket =
      opts.tls === false
        ? {
            host: opts.address,
            port: opts.port,
            tls: false as const,
            connectTimeout: opts.timeoutMs,
            socketTimeout: opts.timeoutMs,
            reconnectStrategy: false as const,
          }
        : {
            host: opts.address,
            port: opts.port,
            tls: true as const,
            rejectUnauthorized: true,
            ca: opts.tls.ca,
            checkServerIdentity: identityCheckerFor(opts.servername ?? opts.host),
            connectTimeout: opts.timeoutMs,
            socketTimeout: opts.timeoutMs,
            reconnectStrategy: false as const,
            ...(servername === undefined ? {} : { servername }),
          };

    // `username:password` splits the same way for every engine (redis legacy
    // servers expose only a password ACL user, conventionally named
    // "default" — this vault always stores redis credentials as
    // "default:<password>" for that case). node-redis accepts both forms
    // through `{ username, password }` and negotiates the right AUTH shape.
    const client = createClient({
      socket,
      username: opts.user,
      password: opts.password,
      database: Number(opts.database),
    });
    // node-redis emits `error` on the client for every socket failure, beside
    // rejecting the pending connect() / sendCommand(). An emitter with no
    // listener throws the event inside the socket's own handler: an uncaught
    // exception for the process and, on a FIN during the handshake, a connect
    // promise that never settles. The rejection carries the error; the event
    // needs only a listener.
    client.on("error", () => {});

    await client.connect();
    try {
      const reply = await client.sendCommand(command as string[]);
      return {
        rows: [reply],
        fields: [{ name: "reply" }],
        rowCount: 1,
        command: undefined,
      };
    } finally {
      try {
        await client.close();
      } catch {
        // best-effort close
      }
    }
  }
}
