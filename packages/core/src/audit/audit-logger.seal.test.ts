import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { generateRandomBytes } from "../crypto/random.js";
import { SqliteStore } from "../storage/sqlite-store.js";
import { withAttribution } from "./attribution.js";
import { AuditLogger } from "./audit-logger.js";
import { AuditQuery } from "./audit-query.js";

let store: SqliteStore;
let auditKey: Uint8Array;
let logger: AuditLogger;

beforeEach(() => {
  store = new SqliteStore(":memory:");
  auditKey = generateRandomBytes(32);
  logger = new AuditLogger(store, auditKey);
});

afterEach(() => {
  vi.restoreAllMocks();
  store.close();
});

describe("AuditLogger.seal", () => {
  it("a sealed logger refuses every write", async () => {
    logger.log({ eventType: AuditEventType.VAULT_UNLOCK });
    const before = store.queryAuditLog().length;
    logger.seal();

    await expectVaultError(
      () => logger.log({ eventType: AuditEventType.SECRET_USE }),
      ErrorCode.VAULT_LOCKED,
    );
    expect(store.queryAuditLog()).toHaveLength(before);
  });

  it("the seal wipes the chain key", () => {
    logger.seal();

    const { chainKey } = logger as unknown as { chainKey: Uint8Array };
    expect(chainKey.every((b) => b === 0)).toBe(true);
  });

  it("a second seal changes nothing", () => {
    logger.seal();

    expect(() => logger.seal()).not.toThrow();
    expect(logger.sealed).toBe(true);
  });
});

describe("the use mark", () => {
  it("a written secret.use row marks its use", () => {
    const use = { recorded: false };

    logger.log(withAttribution({ eventType: AuditEventType.SECRET_USE }, { use }));

    expect(use.recorded).toBe(true);
  });

  it("a row of another type marks nothing", () => {
    const use = { recorded: false };

    logger.log(withAttribution({ eventType: AuditEventType.MCP_TERMINATE }, { use }));

    expect(use.recorded).toBe(false);
  });

  it("a failed insert marks nothing", () => {
    const use = { recorded: false };
    vi.spyOn(store, "insertAuditEvent").mockImplementation(() => {
      throw new Error("disk");
    });

    expect(() =>
      logger.log(withAttribution({ eventType: AuditEventType.SECRET_USE }, { use })),
    ).toThrow("disk");
    expect(use.recorded).toBe(false);
  });

  it("the mark is not stored", () => {
    const detail = { handle: "secret://s1", context: "http" };
    const use = { recorded: false };

    logger.log(
      withAttribution({ eventType: AuditEventType.SECRET_USE, secretId: "s1", detail }, { use }),
    );
    logger.log({ eventType: AuditEventType.SECRET_USE, secretId: "s1", detail });

    expect(use.recorded).toBe(true);
    const [plain, marked] = new AuditQuery(store, auditKey)
      .query()
      .map((row) => ({ ...row, id: 0, timestamp: 0 }));
    expect(marked?.detail).toEqual(detail);
    expect(marked).toStrictEqual(plain);
  });
});
