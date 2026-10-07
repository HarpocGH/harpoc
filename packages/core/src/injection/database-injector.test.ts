import { describe, expect, it, vi } from "vitest";
import type { ConnectionConfig } from "@harpoc/shared";
import { ErrorCode, MAX_DB_RESULT_BYTES } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import type { AuditLogger, AuditLogOptions } from "../audit/audit-logger.js";
import { DatabaseInjector } from "./database-injector.js";
import {
  MockAdapter,
  MockCommandAdapter,
  SECRET,
  action,
  injector,
  policy,
} from "./__fixtures__/database-injector-doubles.js";

describe("DatabaseInjector", () => {
  it("parses username:password and runs the query", async () => {
    const mock = new MockAdapter({ rows: [{ id: 1 }], fields: [{ name: "id" }] });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expect(res.type).toBe("database");
    expect(res.row_count).toBe(1);
    expect(mock.lastConnect?.user).toBe("admin");
    expect(mock.lastConnect?.password).toBe("s3cr3t");
    expect(mock.lastQuery?.sql).toBe("SELECT 1");
  });

  it("requires TLS by default and disables it only via the opt-out", async () => {
    const mock1 = new MockAdapter({ rows: [] });
    await injector(mock1).executeWithSecret(action(), SECRET, policy(), undefined);
    expect(mock1.lastConnect?.tls).not.toBe(false);

    const mock2 = new MockAdapter({ rows: [] });
    const config: ConnectionConfig = { database: { tls_mode: "disable" } };
    await injector(mock2).executeWithSecret(action(), SECRET, policy(), config);
    expect(mock2.lastConnect?.tls).toBe(false);
  });

  it("rejects a host:port outside the allowlist before connecting", async () => {
    const mock = new MockAdapter({ rows: [] });
    await expect(
      injector(mock).executeWithSecret(
        action(),
        SECRET,
        policy({ host_allowlist: ["9.9.9.9"] }),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.HOST_NOT_ALLOWED });
    expect(mock.lastConnect).toBeUndefined();
  });

  it("allows a matching host:port allowlist entry", async () => {
    const mock = new MockAdapter({ rows: [] });
    await injector(mock).executeWithSecret(
      action(),
      SECRET,
      policy({ host_allowlist: ["8.8.8.8:5432"] }),
      undefined,
    );
    expect(mock.lastConnect?.host).toBe("8.8.8.8");
    expect(mock.lastConnect?.port).toBe(5432);
    expect(mock.lastConnect?.address).toBe("8.8.8.8");
  });

  it("blocks SSRF to a private target before connecting", async () => {
    const mock = new MockAdapter({ rows: [] });
    await expect(
      injector(mock).executeWithSecret(action({ host: "10.0.0.1" }), SECRET, policy(), undefined),
    ).rejects.toMatchObject({ code: ErrorCode.SSRF_BLOCKED });
    expect(mock.lastConnect).toBeUndefined();
  });

  it("rejects an unsupported engine", async () => {
    const mock = new MockAdapter({ rows: [] });
    const inj = new DatabaseInjector(null, { postgresql: mock });
    await expect(
      inj.executeWithSecret(action({ engine: "mysql" }), SECRET, policy(), undefined),
    ).rejects.toMatchObject({ code: ErrorCode.UNSUPPORTED_DB_ENGINE });
  });

  // The adapter is resolved ahead of every pre-connect step: a target that
  // would fail all three of them (an out-of-range embedded port that
  // `parseHostPort` would refuse, a host:port `parseHostPort` would produce
  // that the allowlist wouldn't match, and a private address the SSRF floor
  // would block) still refuses as UNSUPPORTED_DB_ENGINE, with exactly one
  // audit row whose detail names no host or port — so a reorder past any one
  // of the three steps would change the error code or the row.
  it("refuses an unsupported engine before parsing, allowlisting or resolving the host", async () => {
    const log = vi.fn();
    const inj = new DatabaseInjector({ log } as unknown as AuditLogger, {
      postgresql: new MockAdapter(),
    });
    await expectVaultError(
      () =>
        inj.executeWithSecret(
          action({ engine: "mysql", host: "10.0.0.1:0" }),
          SECRET,
          policy({ host_allowlist: ["db.example.com:5432"] }),
          undefined,
          "secret-1",
        ),
      ErrorCode.UNSUPPORTED_DB_ENGINE,
    );
    expect(log).toHaveBeenCalledTimes(1);
    const row = log.mock.calls[0]?.[0] as AuditLogOptions;
    expect(row.success).toBe(false);
    expect(row.secretId).toBe("secret-1");
    expect(Object.keys(row.detail ?? {}).sort()).toEqual([
      "context",
      "database",
      "engine",
      "error",
    ]);
    expect(row.detail).toMatchObject({
      context: "database",
      engine: "mysql",
      database: "app",
      error: "UNSUPPORTED_DB_ENGINE",
    });
  });

  it("refuses an unknown SQL engine key in the adapter registry (compile-time)", () => {
    const mock = new MockAdapter({ rows: [] });
    // Compile-time pin: the registry is keyed by DbSqlEngine, so the
    // `"postgres"` fixture that once passed for months is a type error now.
    // @ts-expect-error "postgres" is not a DbSqlEngine
    const inj = new DatabaseInjector(null, { postgres: mock });
    expect(inj).toBeInstanceOf(DatabaseInjector);
  });

  it("refuses a command engine key in the SQL adapter registry (compile-time)", () => {
    const mock = new MockAdapter({ rows: [] });
    // @ts-expect-error redis is a command engine, not a SQL engine
    const inj = new DatabaseInjector(null, { redis: mock });
    expect(inj).toBeInstanceOf(DatabaseInjector);
  });

  it("refuses a SQL engine key in the command-adapter registry (compile-time)", () => {
    const cmd = new MockCommandAdapter();
    // @ts-expect-error postgresql is a SQL engine, not a command engine
    const inj = new DatabaseInjector(null, {}, { postgresql: cmd });
    expect(inj).toBeInstanceOf(DatabaseInjector);
  });

  it("redacts the credential from the result rows", async () => {
    const mock = new MockAdapter({ rows: [{ note: "value is s3cr3t here" }] });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expect(JSON.stringify(res.rows)).not.toContain("s3cr3t");
    expect(JSON.stringify(res.rows)).toContain("[REDACTED]");
  });

  // L1: column names and the command tag are endpoint-authored, so an alias
  // (`SELECT 1 AS "<credential>"`) put the value where no redactor looked while
  // the same string in a row value was redacted.
  it("redacts the credential from a column name", async () => {
    const mock = new MockAdapter({ rows: [{ x: 1 }], fields: [{ name: "s3cr3t" }] });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expect(JSON.stringify(res.fields)).not.toContain("s3cr3t");
    expect(JSON.stringify(res.fields)).toContain("[REDACTED]");
  });

  it("redacts an encoded credential from a column name", async () => {
    const encoded = Buffer.from("s3cr3t", "utf8").toString("base64");
    const mock = new MockAdapter({ rows: [], fields: [{ name: `alias_${encoded}` }] });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expect(JSON.stringify(res.fields)).not.toContain(encoded);
  });

  it("redacts the credential from the command tag", async () => {
    const mock = new MockAdapter({ rows: [], command: "SELECT s3cr3t" });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expect(res.command).not.toContain("s3cr3t");
    expect(res.command).toContain("[REDACTED]");
  });

  it("leaves ordinary column names and command tags untouched", async () => {
    const mock = new MockAdapter({
      rows: [{ id: 1 }],
      fields: [{ name: "id" }, { name: "created_at" }],
      command: "SELECT",
    });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expect(res.fields).toEqual([{ name: "id" }, { name: "created_at" }]);
    expect(res.command).toBe("SELECT");
  });

  it("redacts the credential from a query error and maps to DB_QUERY_FAILED", async () => {
    const mock = new MockAdapter({ queryError: new Error("auth failed for admin:s3cr3t") });
    const err = await expectVaultError(
      () => injector(mock).executeWithSecret(action(), SECRET, policy(), undefined),
      ErrorCode.DB_QUERY_FAILED,
    );
    expect(err.message).not.toContain("s3cr3t");
  });

  it("maps a connection failure to DB_CONNECTION_FAILED", async () => {
    const mock = new MockAdapter({ connectError: new Error("ECONNREFUSED") });
    await expect(
      injector(mock).executeWithSecret(action(), SECRET, policy(), undefined),
    ).rejects.toMatchObject({ code: ErrorCode.DB_CONNECTION_FAILED });
  });

  it("redacts the username half from the result rows", async () => {
    const mock = new MockAdapter({ rows: [{ note: "logged in as admin just now" }] });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expect(JSON.stringify(res.rows)).not.toContain("admin");
    expect(JSON.stringify(res.rows)).toContain("[REDACTED]");
  });

  it("redacts the username half from a query error", async () => {
    const mock = new MockAdapter({ queryError: new Error("permission denied for role admin") });
    const err = await expectVaultError(
      () => injector(mock).executeWithSecret(action(), SECRET, policy(), undefined),
      ErrorCode.DB_QUERY_FAILED,
    );
    expect(err.message).not.toContain("admin");
  });

  it("redacts the username half from a connection error", async () => {
    const mock = new MockAdapter({
      connectError: new Error('password authentication failed for user "admin"'),
    });
    const err = await expectVaultError(
      () => injector(mock).executeWithSecret(action(), SECRET, policy(), undefined),
      ErrorCode.DB_CONNECTION_FAILED,
    );
    expect(err.message).not.toContain("admin");
  });

  it("redacts a username at the shared floor (MIN_REDACTABLE_FRAGMENT)", async () => {
    const mock = new MockAdapter({ rows: [{ note: "logged in as abc just now" }] });
    const res = await injector(mock).executeWithSecret(
      action(),
      new Uint8Array(Buffer.from("abc:s3cr3t")),
      policy(),
      undefined,
    );
    expect(JSON.stringify(res.rows)).not.toContain("abc");
    expect(JSON.stringify(res.rows)).toContain("[REDACTED]");
  });

  it("leaves a 1-2 char username unredacted (would shred unrelated output)", async () => {
    const mock = new MockAdapter({ rows: [{ note: "a value about nothing" }] });
    const res = await injector(mock).executeWithSecret(
      action(),
      new Uint8Array(Buffer.from("ab:s3cr3t")),
      policy(),
      undefined,
    );
    expect(JSON.stringify(res.rows)).toContain("a value about nothing");
  });

  it("refuses an out-of-range embedded port before any connection work", async () => {
    const mock = new MockAdapter({ rows: [] });
    await expect(
      injector(mock).executeWithSecret(
        action({ host: "8.8.8.8:70000" }),
        SECRET,
        policy(),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_DATABASE_CONFIG });
    expect(mock.lastConnect).toBeUndefined();
  });

  it("throws for a secret that is not username:password", async () => {
    const mock = new MockAdapter({ rows: [] });
    await expect(
      injector(mock).executeWithSecret(
        action(),
        new Uint8Array(Buffer.from("no-colon")),
        policy(),
        undefined,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_DATABASE_CONFIG });
  });

  it("flags truncation past the row cap", async () => {
    const rows = Array.from({ length: 10_001 }, (_, i) => ({ i }));
    const mock = new MockAdapter({ rows });
    const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
    expect(res.truncated).toBe(true);
    expect(res.rows.length).toBeLessThanOrEqual(10_000);
  });

  // H5: the byte-cap loop halved with Math.ceil, so a single row larger than the
  // cap never shrank and the loop spun forever. It is synchronous, so this hung
  // the whole vault process — reachable with one agent-chosen query.
  describe("byte cap always terminates (H5)", () => {
    const oversized = (n: number): string => "x".repeat(MAX_DB_RESULT_BYTES + n);

    it("drops a single row that exceeds the byte cap on its own", async () => {
      const mock = new MockAdapter({ rows: [{ blob: oversized(1000) }] });
      const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
      expect(res.truncated).toBe(true);
      expect(res.rows).toEqual([]);
    });

    it("drops the last row when halving bottoms out at one oversized row", async () => {
      const mock = new MockAdapter({
        rows: [{ blob: oversized(1000) }, { blob: oversized(1000) }, { i: 3 }],
      });
      const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
      expect(res.truncated).toBe(true);
      expect(res.rows).toEqual([]);
    });

    it("still returns as many rows as fit under the cap", async () => {
      // 40 rows of ~64 KiB: some fit, so the result must not be emptied.
      const rows = Array.from({ length: 40 }, (_, i) => ({ i, pad: "y".repeat(64 * 1024) }));
      const mock = new MockAdapter({ rows });
      const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
      expect(res.truncated).toBe(true);
      expect(res.rows.length).toBeGreaterThan(0);
      expect(Buffer.byteLength(JSON.stringify(res.rows), "utf8")).toBeLessThanOrEqual(
        MAX_DB_RESULT_BYTES,
      );
    });

    it("negative control: a small result set is returned untruncated", async () => {
      const mock = new MockAdapter({ rows: [{ i: 1 }, { i: 2 }] });
      const res = await injector(mock).executeWithSecret(action(), SECRET, policy(), undefined);
      expect(res.truncated).toBeFalsy();
      expect(res.rows).toHaveLength(2);
    });
  });
});
