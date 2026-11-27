import { describe, expect, it } from "vitest";

import {
  echoField,
  echoHandle,
  num,
  outsidePart,
  renderVaultText,
  token,
  vaultText,
} from "./error-text.js";
import type { TextPart } from "./error-text.js";
import { ErrorCode, VaultError, recordOf, renderRecordedDetails } from "./errors.js";
import type { RecordedDetails } from "./errors.js";

type ErrorRecord = NonNullable<ReturnType<typeof recordOf>>;

const echo = (value: string): TextPart => echoField({ field: value }, "field");

const HANDLE = "secret://project/name";
const DROP_IN_WORDS = ["written", "present", "not_asked", "not_attempted", "refused"];

const FACTORY_ROWS: readonly (readonly [string, () => VaultError, () => VaultError])[] = [
  [
    "invalidInput",
    () => VaultError.invalidInput("the field is out of range"),
    () => VaultError.invalidInput(vaultText`the field is out of range`),
  ],
  [
    "invalidGitConfig",
    () => VaultError.invalidGitConfig("refspec 7 is not allowed"),
    () => VaultError.invalidGitConfig(vaultText`refspec ${num(7)} is not allowed`),
  ],
  [
    "gitOperationFailed",
    () => VaultError.gitOperationFailed("fatal: the remote hung up"),
    () => VaultError.gitOperationFailed(outsidePart("fatal: the remote hung up")),
  ],
  [
    "sshAgentFailed",
    () => VaultError.sshAgentFailed("unsupported key type: ssh-dss"),
    () =>
      VaultError.sshAgentFailed(vaultText`unsupported key type: ${token("ssh-dss", ["ssh-dss"])}`),
  ],
  [
    "imapOperationFailed",
    () => VaultError.imapOperationFailed("imap.example.test:993", "fetch"),
    () => VaultError.imapOperationFailed(echo("imap.example.test:993"), token("fetch", ["fetch"])),
  ],
  [
    "smtpDeliveryFailed",
    () => VaultError.smtpDeliveryFailed("smtp.example.test:587"),
    () => VaultError.smtpDeliveryFailed(echo("smtp.example.test:587")),
  ],
  [
    "hostNotAllowed",
    () => VaultError.hostNotAllowed("db.example.test"),
    () => VaultError.hostNotAllowed(echo("db.example.test")),
  ],
  [
    "urlNotAllowed",
    () => VaultError.urlNotAllowed("https://api.example.test/v1"),
    () => VaultError.urlNotAllowed(echo("https://api.example.test/v1")),
  ],
  [
    "vaultCorrupted",
    () => VaultError.vaultCorrupted("the row is unreadable"),
    () => VaultError.vaultCorrupted(outsidePart("the row is unreadable")),
  ],
  [
    "internalError",
    () => VaultError.internalError("Unexpected engine state"),
    () => VaultError.internalError(vaultText`Unexpected engine state`),
  ],
  [
    "secretRevoked",
    () => VaultError.secretRevoked(HANDLE),
    () => VaultError.secretRevoked(echoHandle(HANDLE)),
  ],
  [
    "secretExpired",
    () => VaultError.secretExpired(HANDLE),
    () => VaultError.secretExpired(echoHandle(HANDLE)),
  ],
  [
    "new VaultError(SECRET_VALUE_REQUIRED)",
    () => new VaultError(ErrorCode.SECRET_VALUE_REQUIRED, `Secret ${HANDLE} has no value set`),
    () =>
      new VaultError(
        ErrorCode.SECRET_VALUE_REQUIRED,
        vaultText`Secret ${echoHandle(HANDLE)} has no value set`,
      ),
  ],
  [
    "mcpConnectFailed",
    () => VaultError.mcpConnectFailed("github", "connection refused"),
    () => VaultError.mcpConnectFailed(echo("github"), outsidePart("connection refused")),
  ],
  [
    "mcpProtocolError",
    () => VaultError.mcpProtocolError("github", "unexpected frame"),
    () => VaultError.mcpProtocolError(echo("github"), outsidePart("unexpected frame")),
  ],
  [
    "mcpServerCrashed",
    () => VaultError.mcpServerCrashed("github", 1, "SIGTERM"),
    () => VaultError.mcpServerCrashed(echo("github"), 1, token("SIGTERM", ["SIGTERM"])),
  ],
  [
    "mcpTimeout",
    () => VaultError.mcpTimeout("github"),
    () => VaultError.mcpTimeout(echo("github")),
  ],
  [
    "mcpServerMismatch",
    () => VaultError.mcpServerMismatch("gitlab", "github"),
    () => VaultError.mcpServerMismatch(echo("gitlab"), outsidePart("github")),
  ],
  [
    "mcpServerNotConfigured",
    () => VaultError.mcpServerNotConfigured(HANDLE),
    () => VaultError.mcpServerNotConfigured(echoHandle(HANDLE)),
  ],
  [
    "commandNotAllowed",
    () => VaultError.commandNotAllowed("/usr/bin/curl"),
    () => VaultError.commandNotAllowed(echo("/usr/bin/curl")),
  ],
  [
    "dedicatedContextRequired",
    () => VaultError.dedicatedContextRequired("git", "git"),
    () => VaultError.dedicatedContextRequired(echo("git"), token("git", ["git"])),
  ],
  [
    "invalidProcessConfig",
    () => VaultError.invalidProcessConfig("args must be strings"),
    () => VaultError.invalidProcessConfig(vaultText`args must be strings`),
  ],
  [
    "networkIsolationUnavailable",
    () => VaultError.networkIsolationUnavailable("unsupported platform: aix"),
    () =>
      VaultError.networkIsolationUnavailable(
        vaultText`unsupported platform: ${token("aix", ["aix"])}`,
      ),
  ],
  [
    "fsIsolationUnavailable",
    () => VaultError.fsIsolationUnavailable("setpriv is missing"),
    () => VaultError.fsIsolationUnavailable(vaultText`setpriv is missing`),
  ],
  [
    "strictTreeExitUnavailable",
    () => VaultError.strictTreeExitUnavailable("the compiler failed"),
    () => VaultError.strictTreeExitUnavailable(outsidePart("the compiler failed")),
  ],
  [
    "responseModeNotAllowed",
    () => VaultError.responseModeNotAllowed("full", "filtered"),
    () =>
      VaultError.responseModeNotAllowed(
        echo("full"),
        token("filtered", ["full", "filtered", "status_only"]),
      ),
  ],
  [
    "responseTooLarge",
    () => VaultError.responseTooLarge("https://api.example.test", 1048576),
    () => VaultError.responseTooLarge(echo("https://api.example.test"), 1048576),
  ],
  [
    "websocketConnectFailed",
    () => VaultError.websocketConnectFailed("wss://ws.example.test"),
    () => VaultError.websocketConnectFailed(echo("wss://ws.example.test")),
  ],
  [
    "smtpStarttlsUnavailable",
    () => VaultError.smtpStarttlsUnavailable("smtp.example.test"),
    () => VaultError.smtpStarttlsUnavailable(echo("smtp.example.test")),
  ],
  [
    "imapMoveUnsupported",
    () => VaultError.imapMoveUnsupported("imap.example.test:993"),
    () => VaultError.imapMoveUnsupported(echo("imap.example.test:993")),
  ],
  [
    "imapMutationNotAllowed",
    () => VaultError.imapMutationNotAllowed("store"),
    () => VaultError.imapMutationNotAllowed(token("store", ["store"])),
  ],
  [
    "recipientNotAllowed",
    () => VaultError.recipientNotAllowed("someone@example.test"),
    () => VaultError.recipientNotAllowed(echo("someone@example.test")),
  ],
  [
    "attachmentRejected",
    () => VaultError.attachmentRejected("too large"),
    () => VaultError.attachmentRejected(vaultText`too large`),
  ],
  [
    "dbConnectionFailed",
    () => VaultError.dbConnectionFailed("connection reset"),
    () => VaultError.dbConnectionFailed(outsidePart("connection reset")),
  ],
  [
    "dbQueryFailed",
    () => VaultError.dbQueryFailed("syntax error"),
    () => VaultError.dbQueryFailed(outsidePart("syntax error")),
  ],
  [
    "unsupportedDbEngine",
    () => VaultError.unsupportedDbEngine("oracle"),
    () => VaultError.unsupportedDbEngine(echo("oracle")),
  ],
  [
    "invalidDatabaseConfig",
    () => VaultError.invalidDatabaseConfig("database name is required"),
    () => VaultError.invalidDatabaseConfig(vaultText`database name is required`),
  ],
  [
    "sshConnectFailed",
    () => VaultError.sshConnectFailed("host.example.test"),
    () => VaultError.sshConnectFailed(echo("host.example.test")),
  ],
  [
    "sshHostKeyMismatch",
    () => VaultError.sshHostKeyMismatch("host.example.test"),
    () => VaultError.sshHostKeyMismatch(echo("host.example.test")),
  ],
  [
    "invalidSshConfig",
    () => VaultError.invalidSshConfig("host is required"),
    () => VaultError.invalidSshConfig(vaultText`host is required`),
  ],
  [
    "sshClientUnsupported",
    () => VaultError.sshClientUnsupported("C:\\Program Files\\Git\\usr\\bin"),
    () => VaultError.sshClientUnsupported(outsidePart("C:\\Program Files\\Git\\usr\\bin")),
  ],
  [
    "gitUnsupportedTransport",
    () => VaultError.gitUnsupportedTransport("ftp://git.example.test/r"),
    () => VaultError.gitUnsupportedTransport(echo("ftp://git.example.test/r")),
  ],
  [
    "sshBootstrapStepFailed",
    () => VaultError.sshBootstrapStepFailed("written", "failed"),
    () =>
      VaultError.sshBootstrapStepFailed(
        token("written", DROP_IN_WORDS),
        token("failed", ["not_attempted", "failed"]),
      ),
  ],
  [
    "sftpOperationFailed",
    () => new VaultError(ErrorCode.SFTP_OPERATION_FAILED, "SFTP operation failed (exit code 3)"),
    () => VaultError.sftpOperationFailed(3),
  ],
  [
    "dockerOperationFailed",
    () =>
      new VaultError(ErrorCode.DOCKER_OPERATION_FAILED, "Docker operation failed (exit code -1)"),
    () => VaultError.dockerOperationFailed(-1),
  ],
  [
    "encryptionError",
    () => VaultError.encryptionError("ciphertext too short"),
    () => VaultError.encryptionError(vaultText`ciphertext too short`),
  ],
  [
    "oauthRefreshFailed",
    () => VaultError.oauthRefreshFailed("HTTP 400"),
    () => VaultError.oauthRefreshFailed(vaultText`HTTP ${num(400)}`),
  ],
];

describe("VaultError's record", () => {
  it("a parameterless factory records its text", () => {
    for (const err of [VaultError.vaultLocked(), VaultError.urlNotAllowed()]) {
      const record = recordOf(err);
      expect(record).toBeDefined();
      expect(renderVaultText((record as ErrorRecord).message)).toBe(err.message);
    }
  });

  it("a factory handed a string records nothing", () => {
    expect(recordOf(VaultError.urlNotAllowed("https://x"))).toBeUndefined();
    expect(recordOf(VaultError.invalidInput("x"))).toBeUndefined();
    expect(recordOf(VaultError.urlNotAllowed(""))).toBeUndefined();
  });

  it("a value that is no part reads as today and records nothing", () => {
    const numeric = VaultError.urlNotAllowed(5 as unknown as string);
    expect(numeric.message).toBe("URL not in secret allowlist: 5");
    expect(recordOf(numeric)).toBeUndefined();
    const object = VaultError.urlNotAllowed({} as unknown as string);
    expect(object.message).toBe("URL not in secret allowlist: [object Object]");
    expect(recordOf(object)).toBeUndefined();
    const rebuilt = new VaultError(ErrorCode.INTERNAL_ERROR, 5 as unknown as string);
    expect(rebuilt.message).toBe("5");
    expect(recordOf(rebuilt)).toBeUndefined();
    const crashed = VaultError.mcpServerCrashed("github", null, undefined as unknown as null);
    expect(crashed.details).toStrictEqual({ server: "github", exit_code: null, signal: undefined });
  });

  it.each(FACTORY_ROWS)(
    "a factory handed a part records it and reads as before: %s",
    (_name, fromStrings, fromParts) => {
      const plain = fromStrings();
      const parted = fromParts();
      expect(parted.message).toBe(plain.message);
      expect(parted.code).toBe(plain.code);
      expect(parted.details).toEqual(plain.details);
      expect(recordOf(plain)).toBeUndefined();
      expect(recordOf(parted)).toBeDefined();
    },
  );

  it("an empty echo gives the text without its suffix", () => {
    const err = VaultError.urlNotAllowed(echoField({ url: "" }, "url"));
    expect(err.message).toBe("URL not in secret allowlist");
    expect(recordOf(err)).toBeDefined();
  });

  it("an empty part that is no echo gives the text without its suffix", () => {
    const err = VaultError.gitOperationFailed(outsidePart(""));
    expect(err.message).toBe("Git operation failed");
    expect(recordOf(err)).toBeDefined();
  });

  it("a response limit beside a string origin reads as today", () => {
    const err = VaultError.responseTooLarge("https://x", NaN);
    expect(err.message).toBe("Response body from https://x exceeds the NaN-byte limit");
    expect(recordOf(err)).toBeUndefined();
  });

  it("a part-shaped value from outside records nothing", () => {
    const forged = JSON.parse('{"kind":"token","text":"anything the sender chose"}') as TextPart;
    const url = VaultError.urlNotAllowed(forged);
    expect(url.message).toBe("URL not in secret allowlist: [object Object]");
    expect(recordOf(url)).toBeUndefined();
    const literal = new VaultError(ErrorCode.INTERNAL_ERROR, {
      parts: [{ kind: "words", text: "raw text" }],
    });
    expect(literal.message).toBe("[object Object]");
    expect(recordOf(literal)).toBeUndefined();
    const details = new VaultError(ErrorCode.MCP_TIMEOUT, vaultText`x`, { server: forged });
    expect(recordOf(details)).toBeUndefined();
  });

  it("a record cannot be changed by a holder of its text or its details", () => {
    const details: Record<string, TextPart> = { server: outsidePart("first") };
    const err = new VaultError(ErrorCode.MCP_TIMEOUT, vaultText`x`, details);
    details.server = outsidePart("second");
    const record = recordOf(err) as ErrorRecord;
    expect(Object.isFrozen(record)).toBe(true);
    expect(Object.isFrozen(record.message)).toBe(true);
    expect(Object.isFrozen(record.details)).toBe(true);
    expect(renderRecordedDetails(record.details as RecordedDetails)).toEqual({ server: "first" });
  });

  it("recorded details render leaf by leaf, an echo from the call", () => {
    const a = { server: "derived" };
    const crashed = VaultError.mcpServerCrashed(echoField(a, "server"), 3, null);
    const details = (recordOf(crashed) as ErrorRecord).details as RecordedDetails;
    expect(renderRecordedDetails(details)).toEqual({
      server: "derived",
      exit_code: 3,
      signal: null,
    });
    expect(renderRecordedDetails(details, { action: { server: "as sent" } })).toEqual({
      server: "as sent",
      exit_code: 3,
      signal: null,
    });
    expect(renderRecordedDetails(details, { action: {} })).toEqual({
      server: "[unreadable]",
      exit_code: 3,
      signal: null,
    });
    expect(renderRecordedDetails({ reason: outsidePart("o"), word: token("a", ["a"]) })).toEqual({
      reason: "o",
      word: "a",
    });
    const forged = JSON.parse('{"kind":"number","text":"7"}') as TextPart;
    expect(renderRecordedDetails({ count: forged })).toEqual({ count: "unknown" });
  });

  it("details of parts are recorded, details of anything else are not", () => {
    const a = { server: "github" };
    const crashed = VaultError.mcpServerCrashed(echoField(a, "server"), 3, null);
    expect(crashed.details).toEqual({ server: a.server, exit_code: 3, signal: null });
    expect(recordOf(crashed)).toBeDefined();

    const killed = VaultError.mcpServerCrashed(
      echoField(a, "server"),
      null,
      token("SIGKILL", ["SIGKILL"]),
    );
    expect(killed.details).toEqual({ server: a.server, exit_code: null, signal: "SIGKILL" });
    expect(recordOf(killed)).toBeDefined();

    const free = new VaultError(ErrorCode.INTERNAL_ERROR, vaultText`x`, { free: "text" });
    expect(free.message).toBe("x");
    expect(free.details).toEqual({ free: "text" });
    expect(recordOf(free)).toBeUndefined();
  });

  it("a copy has no record", () => {
    const e = VaultError.urlNotAllowed(echoField({ url: "https://x/a" }, "url"));
    expect(recordOf(e)).toBeDefined();
    expect(recordOf(structuredClone(e))).toBeUndefined();
    expect(
      recordOf(Object.assign(Object.create(VaultError.prototype) as object, e)),
    ).toBeUndefined();
    expect(recordOf(new VaultError(e.code, e.message, e.details))).toBeUndefined();
    expect(recordOf(JSON.parse(JSON.stringify(e)))).toBeUndefined();

    let caught: unknown;
    try {
      throw e;
    } catch (err) {
      caught = err;
    }
    let thrown: unknown;
    try {
      throw caught;
    } catch (err) {
      thrown = err;
    }
    expect(Object.is(thrown, e)).toBe(true);
    expect(recordOf(thrown)).toBeDefined();
  });
});
