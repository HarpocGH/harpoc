import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { UseSecretAction } from "@harpoc/shared";
import { AuditEventType, ErrorCode, VaultError } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { nonReadAuditCount } from "./__fixtures__/engine-seams.js";
import { VaultEngine } from "./vault-engine.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);

let tempDir: string;
let engine: VaultEngine;

beforeEach(() => {
  tempDir = join(
    tmpdir(),
    `harpoc-use-before-decrypt-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
});

afterEach(async () => {
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

async function initWithSecret(name: string, value: string): Promise<void> {
  await engine.initVault("password");
  await engine.createSecret({
    name,
    type: "api_key",
    value: new Uint8Array(Buffer.from(value)),
  });
}

interface EngineInternals {
  secretManager: {
    getSecretValue: (handle: string) => Promise<Uint8Array>;
    resolveHandle: (handle: string) => Promise<unknown>;
    assertUsable: (...args: unknown[]) => void;
  };
  store: { insertAuditEvent: (...args: unknown[]) => unknown };
  loadInjectionPolicy: (...args: unknown[]) => unknown;
  concealHandleError: (...args: unknown[]) => unknown;
}

const HANDLE = "secret://k";

function unparsed(value: unknown): UseSecretAction {
  return value as UseSecretAction;
}

function internals(): EngineInternals {
  return engine as unknown as EngineInternals;
}

function useRows(
  success?: boolean,
): { detail: Record<string, unknown> | null; success: boolean }[] {
  return engine
    .queryAudit({ eventType: AuditEventType.SECRET_USE })
    .filter((row) => success === undefined || row.success === success)
    .map((row) => ({ detail: row.detail, success: row.success }));
}

describe("useSecret — the door", () => {
  beforeEach(async () => {
    await initWithSecret("k", "value-for-no-injector");
  });

  it("refuses an action that is no object before the handle is read, with no row", async () => {
    const resolveHandle = vi.spyOn(internals().secretManager, "resolveHandle");
    try {
      for (const action of [null, undefined, 5, "http", []]) {
        const before = nonReadAuditCount(engine);
        const err = await expectVaultError(
          () => engine.useSecret(HANDLE, unparsed(action)),
          ErrorCode.INVALID_INPUT,
        );
        expect(err.message).toBe("action must be an object");
        expect(nonReadAuditCount(engine)).toBe(before);
      }
      expect(resolveHandle).not.toHaveBeenCalled();
    } finally {
      resolveHandle.mockRestore();
    }
  });

  it("refuses it the same way for a handle that does not resolve", async () => {
    const before = nonReadAuditCount(engine);
    const err = await expectVaultError(
      () => engine.useSecret("secret://nope", unparsed(null)),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toBe("action must be an object");
    expect(nonReadAuditCount(engine)).toBe(before);
  });

  it("refuses a type that names no context before the decrypt, with no row", async () => {
    const resolveHandle = vi.spyOn(internals().secretManager, "resolveHandle");
    const getSecretValue = vi.spyOn(internals().secretManager, "getSecretValue");
    try {
      const before = nonReadAuditCount(engine);
      const err = await expectVaultError(
        () => engine.useSecret(HANDLE, unparsed({ type: "ftp" })),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe("Unsupported action type: ftp");
      expect(resolveHandle).not.toHaveBeenCalled();
      expect(getSecretValue).not.toHaveBeenCalled();
      expect(nonReadAuditCount(engine)).toBe(before);
    } finally {
      resolveHandle.mockRestore();
      getSecretValue.mockRestore();
    }
  });

  it("a locked vault answers VAULT_LOCKED first", async () => {
    await engine.lock();
    await expectVaultError(() => engine.useSecret(HANDLE, unparsed(null)), ErrorCode.VAULT_LOCKED);
  });

  it("a well-formed action passes the door and reaches its context's own refusal", async () => {
    const getSecretValue = vi.spyOn(internals().secretManager, "getSecretValue");
    try {
      await expectVaultError(
        () =>
          engine.useSecret(
            HANDLE,
            unparsed({
              type: "process",
              command: "harpoc-no-such-binary",
              env_var: "TOKEN",
            }),
          ),
        ErrorCode.COMMAND_NOT_ALLOWED,
      );
      expect(getSecretValue).toHaveBeenCalledTimes(1);
    } finally {
      getSecretValue.mockRestore();
    }
  });
});

const IMAP = {
  type: "imap",
  host: "imap.example.com",
  port: 993,
  mailbox: "INBOX",
};
const IMAP_REFUSAL = "imap operation must be an object with a supported kind";

describe("useSecret — an imap operation the vault cannot serve", () => {
  beforeEach(async () => {
    await initWithSecret("mail", "ops@example.com:mailpass");
  });

  it("an imap action without operation is refused before the decrypt with one failed row", async () => {
    const getSecretValue = vi.spyOn(internals().secretManager, "getSecretValue");
    try {
      const err = await expectVaultError(
        () => engine.useSecret("secret://mail", unparsed(IMAP)),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(IMAP_REFUSAL);
      expect(getSecretValue).not.toHaveBeenCalled();
      const rows = useRows();
      expect(rows).toHaveLength(1);
      expect(rows[0]?.success).toBe(false);
      expect(rows[0]?.detail).toStrictEqual({
        context: "imap",
        host: "imap.example.com",
        mailbox: "INBOX",
        uid_count: 0,
        error: ErrorCode.INVALID_INPUT,
      });
    } finally {
      getSecretValue.mockRestore();
    }
  });

  it("a kind outside the six is refused before the decrypt, and the row names it", async () => {
    const getSecretValue = vi.spyOn(internals().secretManager, "getSecretValue");
    try {
      const err = await expectVaultError(
        () =>
          engine.useSecret("secret://mail", unparsed({ ...IMAP, operation: { kind: "delete" } })),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(IMAP_REFUSAL);
      expect(getSecretValue).not.toHaveBeenCalled();
      expect(useRows()).toHaveLength(1);
      expect(useRows()[0]?.detail).toStrictEqual({
        context: "imap",
        host: "imap.example.com",
        mailbox: "INBOX",
        operation: "delete",
        uid_count: 0,
        error: ErrorCode.INVALID_INPUT,
      });
    } finally {
      getSecretValue.mockRestore();
    }
  });

  it("the mail TLS opt-out's refusal keeps its place ahead of it", async () => {
    await engine.setConnectionConfig("secret://mail", { mail: { tls: false } });
    const err = await expectVaultError(
      () => engine.useSecret("secret://mail", unparsed(IMAP)),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toContain("implicit-TLS-only");
    expect(useRows()).toHaveLength(1);
    expect(useRows()[0]?.detail).not.toHaveProperty("operation");
  });
});

const STARTTLS = {
  type: "smtp",
  host: "smtp.example.com",
  security: "starttls",
  from: "ops@example.com",
  subject: "s",
  text: "t",
};

describe("useSecret — the STARTTLS refusal of a malformed smtp action", () => {
  beforeEach(async () => {
    await initWithSecret("mail", "ops@example.com:mailpass");
    await engine.setConnectionConfig("secret://mail", { mail: { tls: false } });
  });

  it("is refused with one failed row whatever the recipients and attachments look like", async () => {
    const shapes = [
      {},
      { to: 5 },
      { to: "dev@example.com" },
      { to: ["dev@example.com"], cc: 5 },
      { to: ["dev@example.com"], bcc: {} },
      { to: ["dev@example.com"], attachments: "x" },
      { to: ["dev@example.com"], attachments: [null] },
    ];
    const getSecretValue = vi.spyOn(internals().secretManager, "getSecretValue");
    try {
      for (const shape of shapes) {
        const err = await expectVaultError(
          () => engine.useSecret("secret://mail", unparsed({ ...STARTTLS, ...shape })),
          ErrorCode.INVALID_INPUT,
        );
        expect(err.message).toContain("STARTTLS cannot honor");
      }
      expect(getSecretValue).not.toHaveBeenCalled();
      expect(useRows(false)).toHaveLength(shapes.length);
    } finally {
      getSecretValue.mockRestore();
    }
  });

  it("the row names what has its schema's type and nothing else", async () => {
    await expectVaultError(
      () =>
        engine.useSecret(
          "secret://mail",
          unparsed({
            ...STARTTLS,
            to: ["dev@example.com", 5],
            cc: "cc@example.com",
            attachments: [null, { path: "/tmp/a.txt" }, { path: 5 }],
          }),
        ),
      ErrorCode.INVALID_INPUT,
    );
    expect(useRows()[0]?.detail).toStrictEqual({
      context: "smtp",
      host: "smtp.example.com",
      from: "ops@example.com",
      recipients: ["dev@example.com"],
      attachment_paths: ["/tmp/a.txt"],
      attachment_total_bytes: 0,
      error: ErrorCode.INVALID_INPUT,
    });
  });
});

describe("useSecret — a raw throw before the decrypt", () => {
  const ACTION = unparsed({
    type: "http",
    method: "GET",
    url: "https://api.example.com/",
  });
  const FAILED = {
    handle: HANDLE,
    context: "http",
    error: ErrorCode.INTERNAL_ERROR,
  };

  beforeEach(async () => {
    await initWithSecret("k", "value-for-no-injector");
  });

  async function refusedInternally(): Promise<void> {
    const err = await expectVaultError(
      () => engine.useSecret(HANDLE, ACTION),
      ErrorCode.INTERNAL_ERROR,
    );
    expect(err.message).toBe("the use failed unexpectedly");
    const rows = useRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.success).toBe(false);
    expect(rows[0]?.detail).toStrictEqual(FAILED);
    expect(JSON.stringify(rows)).not.toContain("raw-marker");
  }

  it("a raw throw while the handle is resolved leaves one row", async () => {
    const spy = vi
      .spyOn(internals().secretManager, "resolveHandle")
      .mockRejectedValue(new Error("raw-marker"));
    try {
      await refusedInternally();
    } finally {
      spy.mockRestore();
    }
  });

  it("a raw throw while the resolution's error is concealed leaves one row", async () => {
    const resolve = vi
      .spyOn(internals().secretManager, "resolveHandle")
      .mockRejectedValue(new Error("raw-marker"));
    const conceal = vi
      .spyOn(internals(), "concealHandleError")
      .mockRejectedValue(new Error("raw-marker"));
    try {
      await refusedInternally();
    } finally {
      conceal.mockRestore();
      resolve.mockRestore();
    }
  });

  it("a raw throw before the decrypt leaves one row and no raw text", async () => {
    const getSecretValue = vi.spyOn(internals().secretManager, "getSecretValue");
    const spy = vi.spyOn(internals(), "loadInjectionPolicy").mockImplementation(() => {
      throw new TypeError("raw-marker");
    });
    try {
      await refusedInternally();
      const { id } = (await internals().secretManager.resolveHandle(HANDLE)) as { id: string };
      const [row] = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
      expect(row?.secret_id).toBe(id);
      expect(getSecretValue).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
      getSecretValue.mockRestore();
    }
  });

  it("a raw throw in the status block leaves one row", async () => {
    const spy = vi.spyOn(internals().secretManager, "assertUsable").mockImplementation(() => {
      throw new Error("raw-marker");
    });
    try {
      await refusedInternally();
    } finally {
      spy.mockRestore();
    }
  });

  it("a raw throw in the value block leaves one row", async () => {
    const spy = vi
      .spyOn(internals().secretManager, "getSecretValue")
      .mockRejectedValue(new Error("raw-marker"));
    try {
      await refusedInternally();
    } finally {
      spy.mockRestore();
    }
  });

  it("a VaultError passes untouched and gets no row from the net", async () => {
    const spy = vi.spyOn(internals(), "loadInjectionPolicy").mockImplementation(() => {
      throw VaultError.vaultCorrupted("policy");
    });
    try {
      await expectVaultError(() => engine.useSecret(HANDLE, ACTION), ErrorCode.VAULT_CORRUPTED);
      expect(useRows()).toHaveLength(0);
    } finally {
      spy.mockRestore();
    }
  });

  it("a row write that fails leaves as the audit failure, never raw", async () => {
    const policy = vi.spyOn(internals(), "loadInjectionPolicy").mockImplementation(() => {
      throw new TypeError("raw-marker");
    });
    const insert = vi.spyOn(internals().store, "insertAuditEvent").mockImplementation(() => {
      throw new Error("audit unavailable");
    });
    try {
      const err = await expectVaultError(
        () => engine.useSecret(HANDLE, ACTION),
        ErrorCode.INTERNAL_ERROR,
      );
      expect(err.message).toBe("the audit write failed unexpectedly");
    } finally {
      insert.mockRestore();
      policy.mockRestore();
    }
  });
});
