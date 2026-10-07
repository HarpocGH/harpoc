import { describe, expect, it, vi } from "vitest";
import type { ConnectionConfig } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import type { AuditLogger, AuditLogOptions } from "../audit/audit-logger.js";
import { DatabaseInjector } from "./database-injector.js";
import {
  MockAdapter,
  MockCommandAdapter,
  SECRET,
  action,
  policy,
  redisAction,
} from "./__fixtures__/database-injector-doubles.js";

// E81: the audited TLS opt-out is a per-use fact — the connection config
// records the operator's choice, the use row records that the credential
// actually crossed a plaintext leg (the SMTP arm's `tls_opt_out` convention).
describe("DatabaseInjector tls_opt_out audit detail (E81)", () => {
  function loggerSpy(): { log: ReturnType<typeof vi.fn>; logger: AuditLogger } {
    const log = vi.fn();
    return { log, logger: { log } as unknown as AuditLogger };
  }

  const DISABLED: ConnectionConfig = { database: { tls_mode: "disable" } };

  function lastDetail(log: ReturnType<typeof vi.fn>): Record<string, unknown> {
    const calls = log.mock.calls;
    const row = calls[calls.length - 1]?.[0] as AuditLogOptions;
    return (row.detail ?? {}) as Record<string, unknown>;
  }

  it("stamps tls_opt_out on the SQL success row", async () => {
    const { log, logger } = loggerSpy();
    const inj = new DatabaseInjector(logger, { postgresql: new MockAdapter({ rows: [] }) });

    await inj.executeWithSecret(action(), SECRET, policy(), DISABLED, "secret-1");

    expect(lastDetail(log).tls_opt_out).toBe(true);
  });

  it("stamps tls_opt_out on the SQL connection-failure row", async () => {
    const { log, logger } = loggerSpy();
    const inj = new DatabaseInjector(logger, {
      postgresql: new MockAdapter({ connectError: new Error("refused") }),
    });

    await expectVaultError(
      () => inj.executeWithSecret(action(), SECRET, policy(), DISABLED, "secret-1"),
      ErrorCode.DB_CONNECTION_FAILED,
    );

    const detail = lastDetail(log);
    expect(detail.error).toBe("DB_CONNECTION_FAILED");
    expect(detail.tls_opt_out).toBe(true);
  });

  it("stamps tls_opt_out on the SQL query-failure row", async () => {
    const { log, logger } = loggerSpy();
    const inj = new DatabaseInjector(logger, {
      postgresql: new MockAdapter({ queryError: new Error("boom") }),
    });

    await expectVaultError(
      () => inj.executeWithSecret(action(), SECRET, policy(), DISABLED, "secret-1"),
      ErrorCode.DB_QUERY_FAILED,
    );

    const detail = lastDetail(log);
    expect(detail.error).toBe("DB_QUERY_FAILED");
    expect(detail.tls_opt_out).toBe(true);
  });

  it("stamps tls_opt_out on the command-engine success and failure rows", async () => {
    const { log: okLog, logger: okLogger } = loggerSpy();
    const ok = new DatabaseInjector(okLogger, {}, { redis: new MockCommandAdapter() });
    await ok.executeWithSecret(redisAction(), SECRET, policy(), DISABLED, "secret-1");
    expect(lastDetail(okLog).tls_opt_out).toBe(true);

    const { log: failLog, logger: failLogger } = loggerSpy();
    const failing = new DatabaseInjector(
      failLogger,
      {},
      { redis: new MockCommandAdapter({ error: new Error("nope") }) },
    );
    await expectVaultError(
      () => failing.executeWithSecret(redisAction(), SECRET, policy(), DISABLED, "secret-1"),
      ErrorCode.DB_QUERY_FAILED,
    );
    const detail = lastDetail(failLog);
    expect(detail.error).toBe("DB_QUERY_FAILED");
    expect(detail.tls_opt_out).toBe(true);
  });

  it("control: TLS in force leaves the key absent from the row", async () => {
    const { log, logger } = loggerSpy();
    const inj = new DatabaseInjector(logger, { postgresql: new MockAdapter({ rows: [] }) });

    await inj.executeWithSecret(
      action(),
      SECRET,
      policy(),
      { database: { tls_mode: "require" } },
      "secret-1",
    );

    expect(lastDetail(log)).not.toHaveProperty("tls_opt_out");
  });

  it("control: the pre-connect refusals carry no tls_opt_out (the mode is not known yet)", async () => {
    const { log, logger } = loggerSpy();
    const inj = new DatabaseInjector(logger, { postgresql: new MockAdapter({ rows: [] }) });

    await expectVaultError(
      () =>
        inj.executeWithSecret(
          action(),
          SECRET,
          policy({ host_allowlist: ["9.9.9.9"] }),
          DISABLED,
          "secret-1",
        ),
      ErrorCode.HOST_NOT_ALLOWED,
    );

    expect(lastDetail(log)).not.toHaveProperty("tls_opt_out");
  });
});

// E70: the redaction the injector already performed is invisible in the wire
// result (that is the point), so the success row is the only place a reader can
// learn that something was scrubbed out of it.
describe("DatabaseInjector sanitized audit detail (E70)", () => {
  function loggerSpy(): { log: ReturnType<typeof vi.fn>; logger: AuditLogger } {
    const log = vi.fn();
    return { log, logger: { log } as unknown as AuditLogger };
  }

  function lastDetail(log: ReturnType<typeof vi.fn>): Record<string, unknown> {
    const calls = log.mock.calls;
    const row = calls[calls.length - 1]?.[0] as AuditLogOptions;
    return (row.detail ?? {}) as Record<string, unknown>;
  }

  it("stamps sanitized on the success row when a row value carried the credential", async () => {
    const { log, logger } = loggerSpy();
    const inj = new DatabaseInjector(logger, {
      postgresql: new MockAdapter({ rows: [{ note: "value is s3cr3t here" }] }),
    });

    const res = await inj.executeWithSecret(action(), SECRET, policy(), undefined, "secret-1");

    expect(JSON.stringify(res.rows)).toContain("[REDACTED]");
    expect(lastDetail(log)).toMatchObject({ sanitized: true });
  });

  it("leaves the key absent when nothing was redacted", async () => {
    const { log, logger } = loggerSpy();
    const inj = new DatabaseInjector(logger, {
      postgresql: new MockAdapter({
        rows: [{ note: "nothing to see" }],
        fields: [{ name: "note" }],
      }),
    });

    await inj.executeWithSecret(action(), SECRET, policy(), undefined, "secret-1");

    expect(lastDetail(log)).not.toHaveProperty("sanitized");
  });

  it("stamps sanitized on the command-engine success row too", async () => {
    const { log, logger } = loggerSpy();
    const inj = new DatabaseInjector(
      logger,
      {},
      {
        redis: new MockCommandAdapter({
          result: {
            rows: ["s3cr3t"],
            fields: [{ name: "reply" }],
            rowCount: 1,
            command: undefined,
          },
        }),
      },
    );

    await inj.executeWithSecret(redisAction(), SECRET, policy(), undefined, "secret-1");

    expect(lastDetail(log)).toMatchObject({ sanitized: true });
  });
});
