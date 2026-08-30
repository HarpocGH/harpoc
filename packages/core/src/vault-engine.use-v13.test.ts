import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  ConnectionConfig,
  DockerRegistryAction,
  DockerResult,
  ImapAction,
  InjectionPolicy,
  SftpAction,
  SftpResult,
  SmtpAction,
  UseSecretAction,
  WebsocketAction,
  WebsocketResult,
} from "@harpoc/shared";
import { AuditEventType, ErrorCode, VaultError } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { VaultEngine } from "./vault-engine.js";
import type { DockerExecution } from "./injection/docker/docker-injector.js";
import type { ImapExecution, ImapOAuth } from "./injection/imap-injector.js";
import type { SftpExecution } from "./injection/sftp-injector.js";
import type { MailTlsConfig, SmtpExecution, SmtpOAuth } from "./injection/smtp-injector.js";
import type { WebsocketExecution } from "./injection/websocket-injector.js";

vi.mock("./crypto/argon2.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("./crypto/argon2.js")>();
  return {
    ...original,
    deriveKey: async (password: string, salt: Uint8Array) => {
      const { createHash } = await import("node:crypto");
      return new Uint8Array(createHash("sha256").update(password).update(salt).digest());
    },
  };
});

let tempDir: string;
let engine: VaultEngine;

beforeEach(() => {
  tempDir = join(tmpdir(), `harpoc-v13-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
});

afterEach(async () => {
  await engine.destroy();
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
});

// ---------------------------------------------------------------------------
// Fakes for the four v1.3 dispatch seams (smtp, imap, websocket, sftp). The
// engine holds each injector as a field re-read on every `assertUnlocked`, so
// a test installs its fake after unlock exactly as the real injector would
// have been installed.
// ---------------------------------------------------------------------------

interface SmtpCall {
  action: SmtpAction;
  secretValue: string;
  policy: InjectionPolicy;
  connection: MailTlsConfig | undefined;
  oauth: SmtpOAuth | undefined;
}

interface ImapCall {
  action: ImapAction;
  secretValue: string;
  policy: InjectionPolicy;
  connection: MailTlsConfig | undefined;
  oauth: ImapOAuth | undefined;
}

interface WsCall {
  action: WebsocketAction;
  secretValue: string;
  policy: InjectionPolicy;
}

interface SftpCall {
  action: SftpAction;
  secretValue: string;
  policy: InjectionPolicy;
  connection: ConnectionConfig | undefined;
}

interface DockerCall {
  action: DockerRegistryAction;
  secretValue: string;
  policy: InjectionPolicy;
}

interface Seams {
  smtp: SmtpCall[];
  imap: ImapCall[];
  websocket: WsCall[];
  sftp: SftpCall[];
  docker: DockerCall[];
}

type SmtpOutcome = SmtpExecution | (() => never);
// The wire-shaped half only: `sanitized` is supplied separately by
// `SeamOutcomes.imapSanitized`, mirroring how sftp/docker carry the flag.
type ImapOutcome = Omit<ImapExecution, "sanitized"> | (() => never);
type WsOutcome = WebsocketResult | (() => never);
type SftpOutcome = SftpResult | (() => never);
type DockerOutcome = DockerResult | (() => never);

function resolveOutcome<T>(outcome: T | (() => never)): T {
  if (typeof outcome === "function") return (outcome as () => never)();
  return outcome;
}

/** The one engine internal the hoist pins directly: the value-decrypt call. */
interface EngineInternals {
  secretManager: { getSecretValue: (handle: string) => Promise<Uint8Array> };
}

interface EngineSeams {
  smtpInjector: { run: (...args: unknown[]) => Promise<SmtpExecution> };
  imapInjector: { run: (...args: unknown[]) => Promise<ImapExecution> };
  websocketExecutor: (...args: unknown[]) => Promise<WebsocketExecution>;
  sftpExecutor: (...args: unknown[]) => Promise<SftpExecution>;
  dockerExecutor: (...args: unknown[]) => Promise<DockerExecution>;
  processInjector: { executeWithSecret: (...args: unknown[]) => Promise<unknown> };
  databaseInjector: { executeWithSecret: (...args: unknown[]) => Promise<unknown> };
  sshInjector: { executeWithSecret: (...args: unknown[]) => Promise<unknown> };
  gitInjector: { executeWithSecret: (...args: unknown[]) => Promise<unknown> };
}

/**
 * Outcomes for the seams a test drives. The five v1.3 seams take a result or a
 * throwing function; the four pre-v1.3 injector seams are installed only when
 * a test supplies a throw for them, so every other test keeps the real ones.
 */
interface SeamOutcomes {
  smtp?: SmtpOutcome;
  imap?: ImapOutcome;
  imapSanitized?: boolean;
  websocket?: WsOutcome;
  wsSanitized?: boolean;
  sftp?: SftpOutcome;
  sftpSanitized?: boolean;
  docker?: DockerOutcome;
  dockerSanitized?: boolean;
  process?: () => never;
  database?: () => never;
  ssh?: () => never;
  git?: () => never;
}

/**
 * Replace all five v1.3 seams with recording fakes, plus any pre-v1.3 injector
 * seam the test supplies a throw for; returns the call log.
 */
function installSeams(e: VaultEngine, outcomes: SeamOutcomes): Seams {
  const calls: Seams = { smtp: [], imap: [], websocket: [], sftp: [], docker: [] };
  const seams = e as unknown as EngineSeams;

  seams.smtpInjector = {
    run: async (...args: unknown[]) => {
      calls.smtp.push({
        action: args[0] as SmtpAction,
        secretValue: args[1] as string,
        policy: args[2] as InjectionPolicy,
        connection: args[3] as MailTlsConfig | undefined,
        oauth: args[4] as SmtpOAuth | undefined,
      });
      return resolveOutcome(
        outcomes.smtp ?? {
          result: { type: "smtp", accepted: 1, message_id: "<vault@harpoc>" },
          auditDetails: {
            host: "smtp.example.com",
            from: "ops@example.com",
            recipients: ["ops@example.com"],
            attachment_paths: [],
            attachment_total_bytes: 0,
          },
        },
      );
    },
  };

  seams.imapInjector = {
    run: async (...args: unknown[]) => {
      calls.imap.push({
        action: args[0] as ImapAction,
        secretValue: args[1] as string,
        policy: args[2] as InjectionPolicy,
        connection: args[3] as MailTlsConfig | undefined,
        oauth: args[4] as ImapOAuth | undefined,
      });
      const execution: Omit<ImapExecution, "sanitized"> = resolveOutcome(
        outcomes.imap ?? {
          result: { type: "imap", operation: "search", uids: [7] },
          auditDetails: {
            host: "imap.example.com",
            mailbox: "INBOX",
            operation: "search",
            uid_count: 1,
          },
        },
      );
      return { ...execution, sanitized: outcomes.imapSanitized ?? false };
    },
  };

  seams.websocketExecutor = async (...args: unknown[]) => {
    calls.websocket.push({
      action: args[0] as WebsocketAction,
      secretValue: Buffer.from(args[1] as Uint8Array).toString("utf8"),
      policy: args[2] as InjectionPolicy,
    });
    const result: WebsocketResult = resolveOutcome(
      outcomes.websocket ?? { type: "websocket", messages: ["pong"], close_code: 1000 },
    );
    return { result, sanitized: outcomes.wsSanitized ?? false };
  };

  seams.sftpExecutor = async (...args: unknown[]) => {
    calls.sftp.push({
      action: args[0] as SftpAction,
      secretValue: Buffer.from(args[1] as Uint8Array).toString("utf8"),
      policy: args[2] as InjectionPolicy,
      connection: args[3] as ConnectionConfig | undefined,
    });
    const result: SftpResult = resolveOutcome(
      outcomes.sftp ?? { type: "sftp", exit_code: 0, stdout: "", stderr: "" },
    );
    return { result, sanitized: outcomes.sftpSanitized ?? false };
  };

  seams.dockerExecutor = async (...args: unknown[]) => {
    calls.docker.push({
      action: args[0] as DockerRegistryAction,
      secretValue: Buffer.from(args[1] as Uint8Array).toString("utf8"),
      policy: args[2] as InjectionPolicy,
    });
    const result: DockerResult = resolveOutcome(
      outcomes.docker ?? {
        type: "docker_registry",
        operation: "pull",
        exit_code: 0,
        stdout: "",
        stderr: "",
      },
    );
    return { result, sanitized: outcomes.dockerSanitized ?? false };
  };

  if (outcomes.process) seams.processInjector = { executeWithSecret: outcomes.process };
  if (outcomes.database) seams.databaseInjector = { executeWithSecret: outcomes.database };
  if (outcomes.ssh) seams.sshInjector = { executeWithSecret: outcomes.ssh };
  if (outcomes.git) seams.gitInjector = { executeWithSecret: outcomes.git };

  return calls;
}

async function initWithSecret(name: string, value: string): Promise<void> {
  await engine.initVault("password");
  await engine.createSecret({
    name,
    type: "api_key",
    value: new Uint8Array(Buffer.from(value)),
  });
}

function useRows(
  success?: boolean,
): { detail: Record<string, unknown> | null; success: boolean }[] {
  return engine
    .queryAudit({ eventType: AuditEventType.SECRET_USE })
    .filter((row) => success === undefined || row.success === success)
    .map((row) => ({ detail: row.detail, success: row.success }));
}

const SMTP_ACTION: SmtpAction = {
  type: "smtp",
  host: "smtp.example.com",
  security: "tls",
  from: "ops@example.com",
  to: ["dev@example.com"],
  subject: "build finished",
  text: "green",
};

const IMAP_ACTION: ImapAction = {
  type: "imap",
  host: "imap.example.com",
  port: 993,
  mailbox: "INBOX",
  operation: { kind: "search", unseen: true },
};

const SFTP_ACTION: SftpAction = {
  type: "sftp",
  host: "deploy.example.com",
  user: "deploy",
  operation: "list",
  remote_path: "/srv/reports",
};

const WS_ACTION: WebsocketAction = {
  type: "websocket",
  url: "wss://stream.example.com/feed",
  injection: { type: "bearer" },
  message: "ping",
};

// ---------------------------------------------------------------------------
// SMTP
// ---------------------------------------------------------------------------

describe("useSecret (smtp) — engine dispatch", () => {
  beforeEach(async () => {
    await initWithSecret("mail", "ops@example.com:mailpass");
  });

  it("dispatches to the SMTP injector and returns the smtp envelope", async () => {
    const calls = installSeams(engine, {});

    const res = await engine.useSecret("secret://mail", SMTP_ACTION);

    expect(calls.smtp).toHaveLength(1);
    expect(calls.smtp[0]?.secretValue).toBe("ops@example.com:mailpass");
    expect(calls.smtp[0]?.oauth).toBeUndefined();
    expect(res).toEqual({ type: "smtp", accepted: 1, message_id: "<vault@harpoc>" });
  });

  it("writes a successful secret.use row carrying the spec §7.2 smtp details", async () => {
    installSeams(engine, {
      smtp: {
        result: { type: "smtp", accepted: 2, message_id: "<id@harpoc>" },
        auditDetails: {
          host: "smtp.example.com",
          from: "ops@example.com",
          recipients: ["dev@example.com", "qa@example.com"],
          attachment_paths: ["/srv/report.pdf"],
          attachment_total_bytes: 4096,
        },
      },
    });

    await engine.useSecret("secret://mail", SMTP_ACTION);

    const rows = useRows(true);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.detail).toEqual({
      context: "smtp",
      host: "smtp.example.com",
      from: "ops@example.com",
      recipients: ["dev@example.com", "qa@example.com"],
      attachment_paths: ["/srv/report.pdf"],
      attachment_total_bytes: 4096,
    });
  });

  it("threads the connection mail group's CA pin to the injector", async () => {
    await engine.setConnectionConfig("secret://mail", { mail: { tls: { ca: "-----CA-----" } } });
    const calls = installSeams(engine, {});

    await engine.useSecret("secret://mail", SMTP_ACTION);

    expect(calls.smtp[0]?.connection).toEqual({ tls: { ca: "-----CA-----" } });
  });

  it("honors the mail TLS opt-out and records tls_opt_out in the use row", async () => {
    await engine.setConnectionConfig("secret://mail", { mail: { tls: false } });
    const calls = installSeams(engine, {});

    await engine.useSecret("secret://mail", SMTP_ACTION);

    expect(calls.smtp[0]?.connection).toEqual({ tls: false });
    expect(useRows(true)[0]?.detail?.tls_opt_out).toBe(true);
  });

  it("omits tls_opt_out when TLS is in force", async () => {
    installSeams(engine, {});
    await engine.useSecret("secret://mail", SMTP_ACTION);
    expect(useRows(true)[0]?.detail).not.toHaveProperty("tls_opt_out");
  });

  it("writes a failed secret.use row naming the attempted attachments on a denial", async () => {
    installSeams(engine, {
      smtp: () => {
        throw VaultError.recipientNotAllowed("leak@evil.example");
      },
    });

    await expect(
      engine.useSecret("secret://mail", {
        ...SMTP_ACTION,
        attachments: [{ path: "/srv/report.pdf" }],
      }),
    ).rejects.toMatchObject({ code: ErrorCode.RECIPIENT_NOT_ALLOWED });

    const rows = useRows(false);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.detail).toEqual({
      context: "smtp",
      host: "smtp.example.com",
      from: "ops@example.com",
      recipients: ["dev@example.com"],
      // Sizes are only known once the injector has read the files; a denial
      // names what was attempted, with the result-derived counter at zero.
      attachment_paths: ["/srv/report.pdf"],
      attachment_total_bytes: 0,
      error: ErrorCode.RECIPIENT_NOT_ALLOWED,
    });
  });

  it("maps a raw filesystem error out of the injector to a path-free VaultError", async () => {
    installSeams(engine, {
      smtp: () => {
        throw new Error("ENOENT: no such file or directory, stat '/home/agent/.ssh/id_ed25519'");
      },
    });

    const err = (await engine
      .useSecret("secret://mail", {
        ...SMTP_ACTION,
        attachments: [{ path: "/home/agent/.ssh/id_ed25519" }],
      })
      .catch((e: unknown) => e)) as VaultError;

    expect(err).toBeInstanceOf(VaultError);
    expect(err.code).toBe(ErrorCode.FILE_IO_ERROR);
    expect(err.message).not.toContain("id_ed25519");
    expect(useRows(false)[0]?.detail?.error).toBe(ErrorCode.FILE_IO_ERROR);
  });
});

describe("useSecret (smtp) — OAuth arm", () => {
  it("resolves the access token and passes { accessToken, username } to the injector", async () => {
    await engine.initVault("password");
    const { handle, secretId } = await engine.createOAuthSecret("mailbox", {
      provider: "google",
      grant_type: "client_credentials",
      token_endpoint: "https://oauth.example.com/token",
      client_id: "cid",
    });
    await engine.completeOAuthFlow(secretId, "ya29.smtp-access-token");
    const calls = installSeams(engine, {});

    await engine.useSecret(handle, SMTP_ACTION);

    expect(calls.smtp[0]?.oauth).toEqual({
      accessToken: "ya29.smtp-access-token",
      username: "ops@example.com",
    });
  });
});

describe("useSecret (smtp) — STARTTLS cannot honor the mail TLS opt-out (N4)", () => {
  const STARTTLS_ACTION: SmtpAction = { ...SMTP_ACTION, security: "starttls" };

  beforeEach(async () => {
    await initWithSecret("mail", "ops@example.com:mailpass");
    await engine.setConnectionConfig("secret://mail", { mail: { tls: false } });
  });

  it("refuses before the injector and before the value decrypt", async () => {
    const calls = installSeams(engine, {});
    const getSecretValue = vi.spyOn(
      (engine as unknown as EngineInternals).secretManager,
      "getSecretValue",
    );

    try {
      await expectVaultError(
        () => engine.useSecret("secret://mail", STARTTLS_ACTION),
        ErrorCode.INVALID_INPUT,
      );

      expect(calls.smtp).toHaveLength(0);
      expect(getSecretValue).not.toHaveBeenCalled();
    } finally {
      getSecretValue.mockRestore();
    }
  });

  it("audits the refusal as a failed secret.use row WITHOUT tls_opt_out", async () => {
    installSeams(engine, {});

    await engine.useSecret("secret://mail", STARTTLS_ACTION).catch(() => undefined);

    const [row] = useRows(false);
    expect(row?.detail).toMatchObject({
      context: "smtp",
      host: "smtp.example.com",
      error: ErrorCode.INVALID_INPUT,
    });
    expect(row?.detail).not.toHaveProperty("tls_opt_out");
  });

  it("names the conflict and both fixes in the message", async () => {
    installSeams(engine, {});

    const err = (await engine
      .useSecret("secret://mail", STARTTLS_ACTION)
      .catch((e: unknown) => e)) as VaultError;

    expect(err.message).toContain("STARTTLS");
    expect(err.message).toContain("security: tls");
  });
});

// ---------------------------------------------------------------------------
// IMAP
// ---------------------------------------------------------------------------

describe("useSecret (imap) — engine dispatch", () => {
  beforeEach(async () => {
    await initWithSecret("inbox", "ops@example.com:mailpass");
  });

  it("dispatches to the IMAP injector and returns the operation-shaped envelope", async () => {
    const calls = installSeams(engine, {
      imap: {
        result: { type: "imap", operation: "search", uids: [3, 9] },
        auditDetails: {
          host: "imap.example.com",
          mailbox: "INBOX",
          operation: "search",
          uid_count: 2,
        },
      },
    });

    const res = await engine.useSecret("secret://inbox", IMAP_ACTION);

    expect(calls.imap).toHaveLength(1);
    expect(res).toEqual({ type: "imap", operation: "search", uids: [3, 9] });
  });

  it("returns fetched messages under the imap envelope", async () => {
    installSeams(engine, {
      imap: {
        result: {
          type: "imap",
          operation: "fetch",
          messages: [{ uid: 4, flags: ["\\Seen"], text: "hello" }],
        },
        auditDetails: {
          host: "imap.example.com",
          mailbox: "INBOX",
          operation: "fetch",
          uid_count: 1,
        },
      },
    });

    const res = await engine.useSecret("secret://inbox", {
      ...IMAP_ACTION,
      operation: { kind: "fetch", uids: [4], parts: "text" },
    });

    expect(res).toEqual({
      type: "imap",
      operation: "fetch",
      messages: [{ uid: 4, flags: ["\\Seen"], text: "hello" }],
    });
  });

  it("returns the affected count for a mutation", async () => {
    installSeams(engine, {
      imap: {
        result: { type: "imap", operation: "store", affected: 3 },
        auditDetails: {
          host: "imap.example.com",
          mailbox: "INBOX",
          operation: "store",
          uid_count: 3,
        },
      },
    });

    const res = await engine.useSecret("secret://inbox", {
      ...IMAP_ACTION,
      operation: { kind: "store", uids: [1, 2, 3], add_flags: ["\\Seen"] },
    });

    expect(res).toEqual({ type: "imap", operation: "store", affected: 3 });
  });

  it("writes a successful secret.use row carrying the spec §7.2 imap details", async () => {
    installSeams(engine, {
      imap: {
        result: { type: "imap", operation: "search", uids: [3, 9] },
        auditDetails: {
          host: "imap.example.com",
          mailbox: "Archive",
          operation: "search",
          uid_count: 2,
        },
      },
    });

    await engine.useSecret("secret://inbox", { ...IMAP_ACTION, mailbox: "Archive" });

    expect(useRows(true)[0]?.detail).toEqual({
      context: "imap",
      host: "imap.example.com",
      mailbox: "Archive",
      operation: "search",
      uid_count: 2,
    });
  });

  it("writes a failed secret.use row with a zero uid_count on a denial", async () => {
    installSeams(engine, {
      imap: () => {
        throw VaultError.imapMutationNotAllowed("expunge");
      },
    });

    await expect(
      engine.useSecret("secret://inbox", { ...IMAP_ACTION, operation: { kind: "expunge" } }),
    ).rejects.toMatchObject({ code: ErrorCode.IMAP_MUTATION_NOT_ALLOWED });

    expect(useRows(false)[0]?.detail).toEqual({
      context: "imap",
      host: "imap.example.com",
      mailbox: "INBOX",
      operation: "expunge",
      uid_count: 0,
      error: ErrorCode.IMAP_MUTATION_NOT_ALLOWED,
    });
  });

  it("maps a non-VaultError injector throw to a redacted INTERNAL_ERROR and still audits the denial", async () => {
    installSeams(engine, {
      imap: () => {
        throw new Error("boom");
      },
    });

    const err = (await engine
      .useSecret("secret://inbox", IMAP_ACTION)
      .catch((e: unknown) => e)) as VaultError;

    // (b) no raw non-VaultError escapes to the caller.
    expect(err).toBeInstanceOf(VaultError);
    expect(err.code).toBe(ErrorCode.INTERNAL_ERROR);
    expect(err.message).not.toContain("boom");
    // (a) the denial is still audited, with the mapped code.
    expect(useRows(false)[0]?.detail).toEqual({
      context: "imap",
      host: "imap.example.com",
      mailbox: "INBOX",
      operation: "search",
      uid_count: 0,
      error: ErrorCode.INTERNAL_ERROR,
    });
  });

  it("threads the connection mail group's CA pin to the injector", async () => {
    await engine.setConnectionConfig("secret://inbox", { mail: { tls: { ca: "-----CA-----" } } });
    const calls = installSeams(engine, {});

    await engine.useSecret("secret://inbox", IMAP_ACTION);

    expect(calls.imap[0]?.connection).toEqual({ tls: { ca: "-----CA-----" } });
  });
});

describe("useSecret (imap) — mail TLS opt-out is refused (implicit-TLS only)", () => {
  beforeEach(async () => {
    await initWithSecret("inbox", "ops@example.com:mailpass");
    await engine.setConnectionConfig("secret://inbox", { mail: { tls: false } });
  });

  it("refuses before the injector is reached", async () => {
    const calls = installSeams(engine, {});

    await expect(engine.useSecret("secret://inbox", IMAP_ACTION)).rejects.toMatchObject({
      code: ErrorCode.INVALID_INPUT,
    });

    expect(calls.imap).toHaveLength(0);
  });

  it("names the conflict and the admin fix in the message", async () => {
    installSeams(engine, {});

    const err = await engine.useSecret("secret://inbox", IMAP_ACTION).catch((e: unknown) => e);

    const message = (err as VaultError).message;
    expect(message).toContain("implicit-TLS");
    expect(message).toContain("two secrets");
  });

  it("audits the refusal as a failed secret.use row", async () => {
    installSeams(engine, {});

    await engine.useSecret("secret://inbox", IMAP_ACTION).catch(() => undefined);

    expect(useRows(false)[0]?.detail).toEqual({
      context: "imap",
      host: "imap.example.com",
      mailbox: "INBOX",
      operation: "search",
      uid_count: 0,
      error: ErrorCode.INVALID_INPUT,
    });
  });

  it("still honors the same opt-out for the smtp leg (plaintext is an SMTP-only opt-out)", async () => {
    const calls = installSeams(engine, {});

    await engine.useSecret("secret://inbox", SMTP_ACTION);

    expect(calls.smtp[0]?.connection).toEqual({ tls: false });
  });
});

describe("useSecret (imap) — an OAuth-type secret is refused (no XOAUTH2 account name)", () => {
  let oauthHandle: string;

  beforeEach(async () => {
    await engine.initVault("password");
    const { handle, secretId } = await engine.createOAuthSecret("mailbox", {
      provider: "google",
      grant_type: "client_credentials",
      token_endpoint: "https://oauth.example.com/token",
      client_id: "cid",
    });
    oauthHandle = handle;
    await engine.completeOAuthFlow(secretId, "ya29.imap-access-token");
  });

  it("refuses before the injector, so the access token never reaches the wire", async () => {
    const calls = installSeams(engine, {});

    const err = (await engine
      .useSecret(oauthHandle, IMAP_ACTION)
      .catch((e: unknown) => e)) as VaultError;

    expect(calls.imap).toHaveLength(0);
    expect(err.code).toBe(ErrorCode.INVALID_INPUT);
    expect(err.message).toContain("XOAUTH2");
    expect(err.message).not.toContain("ya29.");
  });

  it("audits the refusal as a failed secret.use row", async () => {
    installSeams(engine, {});

    await engine.useSecret(oauthHandle, IMAP_ACTION).catch(() => undefined);

    expect(useRows(false)[0]?.detail).toEqual({
      context: "imap",
      host: "imap.example.com",
      mailbox: "INBOX",
      operation: "search",
      uid_count: 0,
      error: ErrorCode.INVALID_INPUT,
    });
  });
});

describe("useSecret (imap) — OAuth arm (XOAUTH2 via the action's account field)", () => {
  let oauthHandle: string;

  beforeEach(async () => {
    await engine.initVault("password");
    const { handle, secretId } = await engine.createOAuthSecret("mailbox", {
      provider: "google",
      grant_type: "client_credentials",
      token_endpoint: "https://oauth.example.com/token",
      client_id: "cid",
    });
    oauthHandle = handle;
    await engine.completeOAuthFlow(secretId, "ya29.imap-access-token");
  });

  it("resolves the access token and passes { accessToken, username } to the injector", async () => {
    const calls = installSeams(engine, {});

    const res = await engine.useSecret(oauthHandle, {
      ...IMAP_ACTION,
      account: "agent@example.com",
    });

    expect(calls.imap).toHaveLength(1);
    expect(calls.imap[0]?.oauth).toEqual({
      accessToken: "ya29.imap-access-token",
      username: "agent@example.com",
    });
    expect(res).toEqual({ type: "imap", operation: "search", uids: [7] });
  });

  it("still refuses without the account field, naming it in the message", async () => {
    const calls = installSeams(engine, {});

    const err = (await engine
      .useSecret(oauthHandle, IMAP_ACTION)
      .catch((e: unknown) => e)) as VaultError;

    expect(calls.imap).toHaveLength(0);
    expect(err.code).toBe(ErrorCode.INVALID_INPUT);
    expect(err.message).toContain("'account'");
  });
});

describe("useSecret (imap) — the account field is refused for the username:password arm", () => {
  beforeEach(async () => {
    await initWithSecret("inbox", "ops@example.com:mailpass");
  });

  it("refuses before the injector is reached", async () => {
    const calls = installSeams(engine, {});

    const err = (await engine
      .useSecret("secret://inbox", { ...IMAP_ACTION, account: "agent@example.com" })
      .catch((e: unknown) => e)) as VaultError;

    expect(calls.imap).toHaveLength(0);
    expect(err.code).toBe(ErrorCode.INVALID_INPUT);
    expect(err.message).toContain("'account'");
  });

  it("audits the refusal as a failed secret.use row naming the attempted identity", async () => {
    installSeams(engine, {});

    await engine
      .useSecret("secret://inbox", { ...IMAP_ACTION, account: "agent@example.com" })
      .catch(() => undefined);

    expect(useRows(false)[0]?.detail).toEqual({
      context: "imap",
      host: "imap.example.com",
      mailbox: "INBOX",
      operation: "search",
      uid_count: 0,
      auth_account: "agent@example.com",
      error: ErrorCode.INVALID_INPUT,
    });
  });
});

describe("useSecret (imap) — both refusals run before the credential is produced", () => {
  it("the OAuth×imap refusal happens before any token fetch or refresh", async () => {
    // A stub that would succeed: if the refusal is late, the refresh runs to
    // completion — POST, persisted rotation and the `oauth.refresh` row.
    const fetchSpy = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            access_token: "ya29.rotated-access-token",
            refresh_token: "rt-rotated",
            expires_in: 3600,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    );
    vi.stubGlobal("fetch", fetchSpy);
    try {
      await engine.initVault("password");
      const { handle, secretId } = await engine.createOAuthSecret("mailbox", {
        provider: "google",
        grant_type: "client_credentials",
        // Loopback: the SSRF pre-flight skips DNS for it, so a refresh that is
        // allowed to start really does reach the stubbed fetch.
        token_endpoint: "http://127.0.0.1:1/token",
        client_id: "cid",
      });
      // Arm the auto-refresh: an access token expiring inside the 60 s window
      // with a refresh_token beside it is exactly the shape
      // `getOAuthAccessToken` POSTs to the token endpoint for.
      await engine.completeOAuthFlow(
        secretId,
        "ya29.imap-access-token",
        "rt-1",
        Date.now() + 30_000,
      );
      const calls = installSeams(engine, {});

      await expect(engine.useSecret(handle, IMAP_ACTION)).rejects.toMatchObject({
        code: ErrorCode.INVALID_INPUT,
      });

      expect(calls.imap).toHaveLength(0);
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(engine.queryAudit({ eventType: AuditEventType.OAUTH_REFRESH })).toHaveLength(0);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("the tls:false×imap refusal happens before the value decrypt", async () => {
    await initWithSecret("inbox", "ops@example.com:mailpass");
    await engine.setConnectionConfig("secret://inbox", { mail: { tls: false } });
    const calls = installSeams(engine, {});
    const getSecretValue = vi.spyOn(
      (engine as unknown as EngineInternals).secretManager,
      "getSecretValue",
    );

    try {
      await expect(engine.useSecret("secret://inbox", IMAP_ACTION)).rejects.toMatchObject({
        code: ErrorCode.INVALID_INPUT,
      });

      expect(calls.imap).toHaveLength(0);
      expect(getSecretValue).not.toHaveBeenCalled();
    } finally {
      getSecretValue.mockRestore();
    }
  });
});

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

describe("useSecret (websocket) — engine dispatch", () => {
  beforeEach(async () => {
    await initWithSecret("ws", "ws-token-value");
  });

  it("dispatches to the WebSocket injector and returns the websocket envelope", async () => {
    const calls = installSeams(engine, {
      websocket: { type: "websocket", messages: ["a", "b"], close_code: 1000 },
    });

    const res = await engine.useSecret("secret://ws", WS_ACTION);

    expect(calls.websocket).toHaveLength(1);
    expect(calls.websocket[0]?.secretValue).toBe("ws-token-value");
    expect(res).toEqual({ type: "websocket", messages: ["a", "b"], close_code: 1000 });
  });

  it("writes a successful secret.use row carrying the spec §7.2 websocket details", async () => {
    installSeams(engine, {
      websocket: { type: "websocket", messages: ["a", "b"], close_code: 1000 },
    });

    await engine.useSecret("secret://ws", WS_ACTION);

    expect(useRows(true)[0]?.detail).toEqual({
      context: "websocket",
      url: "wss://stream.example.com/feed",
      sent: 1,
      received: 2,
    });
  });

  it("writes a failed secret.use row with received 0 on a connect failure", async () => {
    installSeams(engine, {
      websocket: () => {
        throw VaultError.websocketConnectFailed("wss://stream.example.com");
      },
    });

    await expect(engine.useSecret("secret://ws", WS_ACTION)).rejects.toMatchObject({
      code: ErrorCode.WEBSOCKET_CONNECT_FAILED,
    });

    expect(useRows(false)[0]?.detail).toEqual({
      context: "websocket",
      url: "wss://stream.example.com/feed",
      sent: 1,
      received: 0,
      error: ErrorCode.WEBSOCKET_CONNECT_FAILED,
    });
  });

  it("maps a non-VaultError executor throw to a redacted INTERNAL_ERROR and still audits the denial", async () => {
    installSeams(engine, {
      websocket: () => {
        throw new Error("boom");
      },
    });

    const err = (await engine
      .useSecret("secret://ws", WS_ACTION)
      .catch((e: unknown) => e)) as VaultError;

    expect(err).toBeInstanceOf(VaultError);
    expect(err.code).toBe(ErrorCode.INTERNAL_ERROR);
    expect(err.message).not.toContain("boom");
    expect(useRows(false)[0]?.detail).toEqual({
      context: "websocket",
      url: "wss://stream.example.com/feed",
      sent: 1,
      received: 0,
      error: ErrorCode.INTERNAL_ERROR,
    });
  });
});

// ---------------------------------------------------------------------------
// SFTP
// ---------------------------------------------------------------------------

describe("useSecret (sftp) — engine dispatch", () => {
  beforeEach(async () => {
    await initWithSecret("deploy", "FAKE-PRIVATE-KEY-PEM");
  });

  it("dispatches to the sftp executor and returns the process-shaped envelope", async () => {
    const calls = installSeams(engine, {
      sftp: { type: "sftp", exit_code: 0, stdout: "file1\nfile2\n", stderr: "" },
    });

    const res = await engine.useSecret("secret://deploy", SFTP_ACTION);

    expect(calls.sftp).toHaveLength(1);
    expect(calls.sftp[0]?.secretValue).toBe("FAKE-PRIVATE-KEY-PEM");
    expect(res).toEqual({ type: "sftp", exit_code: 0, stdout: "file1\nfile2\n", stderr: "" });
  });

  it("writes a successful secret.use row carrying the spec §7.2 sftp details", async () => {
    installSeams(engine, { sftp: { type: "sftp", exit_code: 0, stdout: "", stderr: "" } });

    await engine.useSecret("secret://deploy", {
      ...SFTP_ACTION,
      operation: "upload",
      remote_path: "/srv/report.pdf",
      local_path: "/tmp/report.pdf",
    });

    expect(useRows(true)).toHaveLength(1);
    expect(useRows(true)[0]?.detail).toEqual({
      context: "sftp",
      host: "deploy.example.com",
      operation: "upload",
      port: null,
      remote_path: "/srv/report.pdf",
      local_path: "/tmp/report.pdf",
    });
  });

  it("writes a failed secret.use row naming the attempted host/operation/paths on a denial", async () => {
    installSeams(engine, {
      sftp: () => {
        throw VaultError.hostNotAllowed("deploy.example.com");
      },
    });

    await expect(engine.useSecret("secret://deploy", SFTP_ACTION)).rejects.toMatchObject({
      code: ErrorCode.HOST_NOT_ALLOWED,
    });

    const rows = useRows(false);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.detail).toEqual({
      context: "sftp",
      host: "deploy.example.com",
      operation: "list",
      port: null,
      remote_path: "/srv/reports",
      local_path: null,
      error: ErrorCode.HOST_NOT_ALLOWED,
    });
  });

  it("writes a failed secret.use row for a graceful (non-throwing) timeout result", async () => {
    installSeams(engine, {
      sftp: {
        type: "sftp",
        exit_code: null,
        stdout: "",
        stderr: "",
        timed_out: true,
        error: ErrorCode.PROCESS_TIMEOUT,
      },
    });

    const res = await engine.useSecret("secret://deploy", SFTP_ACTION);

    expect(res).toMatchObject({ error: ErrorCode.PROCESS_TIMEOUT });
    expect(useRows(false)[0]?.detail).toEqual({
      context: "sftp",
      host: "deploy.example.com",
      operation: "list",
      port: null,
      remote_path: "/srv/reports",
      local_path: null,
      error: ErrorCode.PROCESS_TIMEOUT,
    });
  });

  it("maps a non-VaultError executor throw to a redacted INTERNAL_ERROR and still audits the denial", async () => {
    installSeams(engine, {
      sftp: () => {
        throw new Error("boom");
      },
    });

    const err = (await engine
      .useSecret("secret://deploy", SFTP_ACTION)
      .catch((e: unknown) => e)) as VaultError;

    expect(err).toBeInstanceOf(VaultError);
    expect(err.code).toBe(ErrorCode.INTERNAL_ERROR);
    expect(err.message).not.toContain("boom");
    expect(useRows(false)[0]?.detail).toEqual({
      context: "sftp",
      host: "deploy.example.com",
      operation: "list",
      port: null,
      remote_path: "/srv/reports",
      local_path: null,
      error: ErrorCode.INTERNAL_ERROR,
    });
  });

  it("threads the connection ssh known_hosts group to the executor (reused unchanged, design §5.5)", async () => {
    await engine.setConnectionConfig("secret://deploy", {
      ssh: { known_hosts: ["deploy.example.com ssh-ed25519 AAAA"] },
    });
    const calls = installSeams(engine, {});

    await engine.useSecret("secret://deploy", SFTP_ACTION);

    expect(calls.sftp[0]?.connection).toEqual({
      ssh: { known_hosts: ["deploy.example.com ssh-ed25519 AAAA"] },
    });
  });

  // Ruling 2: isolation flags pass through to the injector's spawnCaptured
  // options exactly like ssh — there is no engine-level refusal for sftp
  // (that refusal is docker-only, see below). The fake executor never
  // reaches a real spawn, so this pins only the engine's own dispatch path.
  it("passes isolation-enabled policies through without an engine-level refusal", async () => {
    await engine.setInjectionPolicy("secret://deploy", {
      network_isolation: true,
      fs_isolation: true,
    });
    const calls = installSeams(engine, {});

    await engine.useSecret("secret://deploy", SFTP_ACTION);

    expect(calls.sftp).toHaveLength(1);
    expect(calls.sftp[0]?.policy.network_isolation).toBe(true);
    expect(calls.sftp[0]?.policy.fs_isolation).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Docker × isolation — engine-level refusal, before any dispatch arm
// ---------------------------------------------------------------------------

const DOCKER_ACTION: UseSecretAction = {
  type: "docker_registry",
  operation: "pull",
  image: "registry.example.com/app:1.0",
  timeout_ms: 300_000,
};

describe("docker_registry × isolation — refused before the dispatch arm", () => {
  beforeEach(async () => {
    await initWithSecret("reg", "robot:regpass");
  });

  it("refuses under network_isolation with NETWORK_ISOLATION_UNAVAILABLE", async () => {
    await engine.setInjectionPolicy("secret://reg", { network_isolation: true });

    const err = (await engine
      .useSecret("secret://reg", DOCKER_ACTION)
      .catch((e: unknown) => e)) as VaultError;

    // The T14 stub arm must never be reached: it throws INTERNAL_ERROR.
    expect(err.code).not.toBe(ErrorCode.INTERNAL_ERROR);
    expect(err.code).toBe(ErrorCode.NETWORK_ISOLATION_UNAVAILABLE);
    expect(err.message).toContain("Docker daemon boundary");
    expect(err.message).toContain("--no-network-isolation");
  });

  it("refuses under fs_isolation with FS_ISOLATION_UNAVAILABLE", async () => {
    await engine.setInjectionPolicy("secret://reg", { fs_isolation: true });

    const err = (await engine
      .useSecret("secret://reg", DOCKER_ACTION)
      .catch((e: unknown) => e)) as VaultError;

    expect(err.code).not.toBe(ErrorCode.INTERNAL_ERROR);
    expect(err.code).toBe(ErrorCode.FS_ISOLATION_UNAVAILABLE);
    expect(err.message).toContain("Docker daemon boundary");
  });

  it("gives the network refusal precedence when both flags are set", async () => {
    await engine.setInjectionPolicy("secret://reg", {
      network_isolation: true,
      fs_isolation: true,
    });

    const err = (await engine
      .useSecret("secret://reg", DOCKER_ACTION)
      .catch((e: unknown) => e)) as VaultError;

    expect(err.code).toBe(ErrorCode.NETWORK_ISOLATION_UNAVAILABLE);
  });

  it("audits the refusal as a failed secret.use row", async () => {
    await engine.setInjectionPolicy("secret://reg", { network_isolation: true });

    await engine.useSecret("secret://reg", DOCKER_ACTION).catch(() => undefined);

    expect(useRows(false)[0]?.detail).toEqual({
      context: "docker_registry",
      image: "registry.example.com/app:1.0",
      operation: "pull",
      network_isolation: true,
      error: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE,
    });
  });

  it("leaves the request-mediated v1.3 contexts unaffected by the isolation flags", async () => {
    await engine.setInjectionPolicy("secret://reg", {
      network_isolation: true,
      fs_isolation: true,
    });
    const calls = installSeams(engine, {});

    await engine.useSecret("secret://reg", SMTP_ACTION);
    await engine.useSecret("secret://reg", IMAP_ACTION);
    await engine.useSecret("secret://reg", WS_ACTION);

    expect(calls.smtp).toHaveLength(1);
    expect(calls.imap).toHaveLength(1);
    expect(calls.websocket).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Docker registry — engine dispatch (isolation-free path, T14)
// ---------------------------------------------------------------------------

describe("useSecret (docker_registry) — engine dispatch", () => {
  beforeEach(async () => {
    await initWithSecret("reg", "robot:regpass");
  });

  it("dispatches to the docker executor and returns the process-shaped envelope", async () => {
    const calls = installSeams(engine, {
      docker: {
        type: "docker_registry",
        operation: "pull",
        exit_code: 0,
        stdout: "Pulled\n",
        stderr: "",
      },
    });

    const res = await engine.useSecret("secret://reg", DOCKER_ACTION);

    expect(calls.docker).toHaveLength(1);
    expect(calls.docker[0]?.secretValue).toBe("robot:regpass");
    expect(res).toEqual({
      type: "docker_registry",
      operation: "pull",
      exit_code: 0,
      stdout: "Pulled\n",
      stderr: "",
    });
  });

  it("writes a successful secret.use row carrying the spec §7.2 docker details", async () => {
    installSeams(engine, {});

    await engine.useSecret("secret://reg", DOCKER_ACTION);

    expect(useRows(true)).toHaveLength(1);
    expect(useRows(true)[0]?.detail).toEqual({
      context: "docker_registry",
      registry: "registry.example.com",
      image: "registry.example.com/app:1.0",
      operation: "pull",
    });
  });

  it("writes a failed secret.use row naming the registry/image/operation on a denial", async () => {
    installSeams(engine, {
      docker: () => {
        throw VaultError.hostNotAllowed("registry.example.com");
      },
    });

    await expect(engine.useSecret("secret://reg", DOCKER_ACTION)).rejects.toMatchObject({
      code: ErrorCode.HOST_NOT_ALLOWED,
    });

    const rows = useRows(false);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.detail).toEqual({
      context: "docker_registry",
      registry: "registry.example.com",
      image: "registry.example.com/app:1.0",
      operation: "pull",
      error: ErrorCode.HOST_NOT_ALLOWED,
    });
  });

  it("writes a failed secret.use row for a graceful (non-throwing) timeout result", async () => {
    installSeams(engine, {
      docker: {
        type: "docker_registry",
        operation: "pull",
        exit_code: null,
        stdout: "",
        stderr: "",
        timed_out: true,
        error: ErrorCode.PROCESS_TIMEOUT,
      },
    });

    const res = await engine.useSecret("secret://reg", DOCKER_ACTION);

    expect(res).toMatchObject({ error: ErrorCode.PROCESS_TIMEOUT });
    expect(useRows(false)[0]?.detail).toEqual({
      context: "docker_registry",
      registry: "registry.example.com",
      image: "registry.example.com/app:1.0",
      operation: "pull",
      error: ErrorCode.PROCESS_TIMEOUT,
    });
  });

  it("maps a non-VaultError executor throw to a redacted INTERNAL_ERROR and still audits the denial", async () => {
    installSeams(engine, {
      docker: () => {
        throw new Error("boom");
      },
    });

    const err = (await engine
      .useSecret("secret://reg", DOCKER_ACTION)
      .catch((e: unknown) => e)) as VaultError;

    expect(err).toBeInstanceOf(VaultError);
    expect(err.code).toBe(ErrorCode.INTERNAL_ERROR);
    expect(err.message).not.toContain("boom");
    expect(useRows(false)[0]?.detail).toEqual({
      context: "docker_registry",
      registry: "registry.example.com",
      image: "registry.example.com/app:1.0",
      operation: "pull",
      error: ErrorCode.INTERNAL_ERROR,
    });
  });

  // The isolation guard fires BEFORE this arm: a docker × isolation secret is
  // refused and the injector fake must never be reached (pins the ordering that
  // keeps the Task 12 refusal in front of the T14 dispatch).
  it("never reaches the injector fake when isolation is set on the secret", async () => {
    await engine.setInjectionPolicy("secret://reg", { network_isolation: true });
    const calls = installSeams(engine, {});

    await expect(engine.useSecret("secret://reg", DOCKER_ACTION)).rejects.toMatchObject({
      code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE,
    });

    expect(calls.docker).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Redis/Mongo route through the EXISTING database arm (Ruling 1 — no new arm)
// ---------------------------------------------------------------------------

describe("redis/mongodb route through the existing database arm", () => {
  beforeEach(async () => {
    await initWithSecret("kv", "default:kvpass");
    await engine.setInjectionPolicy("secret://kv", { host_allowlist: ["cache.internal:6379"] });
  });

  it("audits a refused redis action under the database context", async () => {
    await expect(
      engine.useSecret("secret://kv", {
        type: "database",
        engine: "redis",
        host: "8.8.8.8",
        database: "app",
        command: ["GET", "key"],
      }),
    ).rejects.toMatchObject({ code: ErrorCode.HOST_NOT_ALLOWED });

    const row = useRows(false)[0];
    expect(row?.detail?.context).toBe("database");
    expect(row?.detail?.engine).toBe("redis");
  });

  it("audits a refused mongodb action under the database context", async () => {
    await expect(
      engine.useSecret("secret://kv", {
        type: "database",
        engine: "mongodb",
        host: "8.8.8.8",
        database: "app",
        command: { ping: 1 },
      }),
    ).rejects.toMatchObject({ code: ErrorCode.HOST_NOT_ALLOWED });

    const row = useRows(false)[0];
    expect(row?.detail?.context).toBe("database");
    expect(row?.detail?.engine).toBe("mongodb");
  });
});

// ---------------------------------------------------------------------------
// The thrown-error choke point (E69 + N16)
// ---------------------------------------------------------------------------

describe("useSecret — thrown-error choke point (E69 + N16)", () => {
  const VALUE = "tok-4b1d-secret-value";

  const throwCarryingValue = (): never => {
    throw new VaultError(ErrorCode.GIT_OPERATION_FAILED, `fatal: ${VALUE}`, { where: VALUE });
  };

  // `failedRows` is the arm's own bookkeeping, not the choke point's: only the
  // sftp arm audits inside the engine, so the four injector-audited arms leave
  // no row once their injector is replaced by a throwing fake.
  const cases: [string, UseSecretAction, SeamOutcomes, number][] = [
    [
      "process",
      { type: "process", command: "x", env_var: "T" },
      { process: throwCarryingValue },
      0,
    ],
    [
      "git",
      { type: "git", operation: "clone", repository: "https://8.8.8.8/o/r.git" },
      { git: throwCarryingValue },
      0,
    ],
    [
      "ssh",
      { type: "ssh", host: "h.example", user: "u", command: "id" },
      { ssh: throwCarryingValue },
      0,
    ],
    [
      "sftp",
      { type: "sftp", host: "h.example", user: "u", operation: "list", remote_path: "/" },
      { sftp: throwCarryingValue },
      1,
    ],
    [
      "database",
      { type: "database", engine: "postgresql", host: "8.8.8.8", database: "d", query: "select 1" },
      { database: throwCarryingValue },
      0,
    ],
  ];

  it.each(cases)(
    "%s: a VaultError carrying the value is rethrown redacted, code preserved",
    async (_kind, action, outcomes, failedRows) => {
      await initWithSecret("k", VALUE);
      installSeams(engine, outcomes);

      const err = (await engine
        .useSecret("secret://k", action)
        .catch((e: unknown) => e)) as VaultError;

      expect(err).toBeInstanceOf(VaultError);
      expect(err.code).toBe(ErrorCode.GIT_OPERATION_FAILED);
      expect(err.message).toContain("[REDACTED]");
      expect(err.message).not.toContain(VALUE);
      expect(JSON.stringify(err.details ?? {})).not.toContain(VALUE);
      expect(useRows(false)).toHaveLength(failedRows);
    },
  );

  it("a raw Error out of the git seam becomes a value-free INTERNAL_ERROR with one failed secret.use row", async () => {
    await initWithSecret("k", VALUE);
    installSeams(engine, {
      git: () => {
        throw new Error(`ENOENT ${VALUE}`);
      },
    });

    const err = (await engine
      .useSecret("secret://k", {
        type: "git",
        operation: "clone",
        repository: "https://8.8.8.8/o/r.git",
      })
      .catch((e: unknown) => e)) as VaultError;

    expect(err.code).toBe(ErrorCode.INTERNAL_ERROR);
    expect(err.message).not.toContain(VALUE);

    const failed = useRows(false);
    expect(failed).toHaveLength(1);
    expect(failed[0]?.detail).toMatchObject({ context: "git", error: ErrorCode.INTERNAL_ERROR });
  });
});

describe("useSecret — status precedes the pre-decrypt guards (Wave 2, B21)", () => {
  it("an expired-but-untransitioned secret × imap tls:false reports SECRET_EXPIRED and transitions", async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "inbox",
      type: "api_key",
      value: new Uint8Array(Buffer.from("ops@example.com:mailpass")),
      expiresAt: Date.now() - 1_000,
    });
    await engine.setConnectionConfig("secret://inbox", { mail: { tls: false } });
    const calls = installSeams(engine, {});

    await expectVaultError(
      () => engine.useSecret("secret://inbox", IMAP_ACTION),
      ErrorCode.SECRET_EXPIRED,
    );

    expect(calls.imap).toHaveLength(0);
    expect(engine.queryAudit({ eventType: AuditEventType.SECRET_EXPIRE })).toHaveLength(1);
    expect(useRows(false)[0]?.detail).toMatchObject({
      context: "imap",
      error: ErrorCode.SECRET_EXPIRED,
    });
    expect((await engine.getSecretInfo("secret://inbox")).status).toBe("expired");
  });

  it("a PENDING OAuth secret × imap reports OAUTH_NOT_CONFIGURED, not INVALID_INPUT", async () => {
    await engine.initVault("password");
    const { handle } = await engine.createOAuthSecret("mailbox", {
      provider: "google",
      grant_type: "client_credentials",
      token_endpoint: "https://oauth.example.com/token",
      client_id: "cid",
    });
    const calls = installSeams(engine, {});

    const err = await expectVaultError(
      () => engine.useSecret(handle, IMAP_ACTION),
      ErrorCode.OAUTH_NOT_CONFIGURED,
    );

    expect(err.message).toBe("OAuth not configured for secret: OAuth flow not completed");
    expect(calls.imap).toHaveLength(0);
  });

  it("a revoked secret × smtp starttls with tls:false reports SECRET_REVOKED", async () => {
    await initWithSecret("outbox", "ops@example.com:mailpass");
    await engine.setConnectionConfig("secret://outbox", { mail: { tls: false } });
    await engine.revokeSecret("secret://outbox");
    const calls = installSeams(engine, {});

    await expectVaultError(
      () => engine.useSecret("secret://outbox", { ...SMTP_ACTION, security: "starttls" }),
      ErrorCode.SECRET_REVOKED,
    );
    expect(calls.smtp).toHaveLength(0);
  });

  it("an expired secret × docker isolation reports SECRET_EXPIRED before the isolation refusal", async () => {
    await engine.initVault("password");
    await engine.createSecret({
      name: "reg",
      type: "api_key",
      value: new Uint8Array(Buffer.from("robot:regpass")),
      expiresAt: Date.now() - 1_000,
    });
    await engine.setInjectionPolicy("secret://reg", { network_isolation: true });

    await expectVaultError(
      () => engine.useSecret("secret://reg", DOCKER_ACTION),
      ErrorCode.SECRET_EXPIRED,
    );
  });

  it("control: an ACTIVE secret still refuses the architectural conflict with INVALID_INPUT", async () => {
    await initWithSecret("inbox2", "ops@example.com:mailpass");
    await engine.setConnectionConfig("secret://inbox2", { mail: { tls: false } });
    installSeams(engine, {});

    await expectVaultError(
      () => engine.useSecret("secret://inbox2", IMAP_ACTION),
      ErrorCode.INVALID_INPUT,
    );
  });
});

describe("useSecret — sanitized rides the success row (Wave 2, E70)", () => {
  it("sftp: the row carries sanitized: true when the executor redacted", async () => {
    await initWithSecret("deploy", "FAKE-PRIVATE-KEY-PEM");
    installSeams(engine, {
      sftp: { type: "sftp", exit_code: 0, stdout: "file1\n", stderr: "" },
      sftpSanitized: true,
    });
    await engine.useSecret("secret://deploy", SFTP_ACTION);
    expect(useRows(true)[0]?.detail).toMatchObject({ context: "sftp", sanitized: true });
  });

  it("imap: the row carries sanitized: true when the injector redacted", async () => {
    await initWithSecret("inbox", "ops@example.com:mailpass");
    installSeams(engine, { imapSanitized: true });
    await engine.useSecret("secret://inbox", IMAP_ACTION);
    expect(useRows(true)[0]?.detail).toMatchObject({ context: "imap", sanitized: true });
  });

  it("websocket: the row carries sanitized: true when the executor redacted", async () => {
    await initWithSecret("stream", "ws-token-value");
    installSeams(engine, { wsSanitized: true });
    await engine.useSecret("secret://stream", WS_ACTION);
    expect(useRows(true)[0]?.detail).toMatchObject({ context: "websocket", sanitized: true });
  });

  it("websocket: the key is absent when nothing was redacted", async () => {
    await initWithSecret("stream", "ws-token-value");
    installSeams(engine, {});
    await engine.useSecret("secret://stream", WS_ACTION);
    expect("sanitized" in (useRows(true)[0]?.detail ?? {})).toBe(false);
  });

  it("docker: the row carries sanitized: true when the executor redacted", async () => {
    await initWithSecret("reg", "robot:regpass");
    installSeams(engine, {
      docker: {
        type: "docker_registry",
        operation: "pull",
        exit_code: 0,
        stdout: "Pulled",
        stderr: "",
      },
      dockerSanitized: true,
    });
    await engine.useSecret("secret://reg", DOCKER_ACTION);
    expect(useRows(true)[0]?.detail).toMatchObject({
      context: "docker_registry",
      sanitized: true,
    });
  });

  it("docker: the key is absent when nothing was redacted", async () => {
    await initWithSecret("reg", "robot:regpass");
    installSeams(engine, {
      docker: {
        type: "docker_registry",
        operation: "pull",
        exit_code: 0,
        stdout: "Pulled\n",
        stderr: "",
      },
    });
    await engine.useSecret("secret://reg", DOCKER_ACTION);
    expect(useRows(true)).toHaveLength(1);
    expect("sanitized" in (useRows(true)[0]?.detail ?? {})).toBe(false);
  });
});
