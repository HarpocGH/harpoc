import { randomUUID } from "node:crypto";
import { promises as dnsPromises } from "node:dns";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { createServer as createNetServer } from "node:net";
import type { AddressInfo, Server as NetServer, Socket } from "node:net";
import { tmpdir } from "node:os";
import { delimiter, join, sep } from "node:path";
import { TLSSocket, createSecureContext } from "node:tls";
import { NodeStreamableHTTPServerTransport } from "@modelcontextprotocol/node";
import { McpServer } from "@modelcontextprotocol/server";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock, MockInstance } from "vitest";
import type {
  DatabaseAction,
  DockerRegistryAction,
  GitAction,
  HttpAction,
  InjectionPolicyInput,
  MailConnectionConfig,
  McpServerConfigInput,
  SmtpAction,
  UseSecretAction,
} from "@harpoc/shared";
import {
  AAD_CONNECTION_CONFIG,
  AAD_MCP_SERVER_CONFIG,
  ErrorCode,
  MAX_ATTACHMENT_BYTES,
  MAX_ATTACHMENT_TOTAL_BYTES,
  MAX_HTTP_RESPONSE_BYTES,
  MAX_SMTP_ATTACHMENTS,
  VaultError,
  echoField,
  vaultText,
} from "@harpoc/shared";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";
import { retainDecryptedValues } from "./__fixtures__/engine-seams.js";
import type { AuditLogger } from "./audit/audit-logger.js";
import { encrypt } from "./crypto/aes-gcm.js";
import {
  MockAdapter,
  MockCommandAdapter,
} from "./injection/__fixtures__/database-injector-doubles.js";
import { resolveSupportedGit } from "./injection/__fixtures__/supported-git.js";
import { TEST_SERVER } from "./injection/__fixtures__/mcp-downstream.js";
import { DatabaseInjector } from "./injection/database-injector.js";
import type { DbCommandAdapter, DbEngineAdapter } from "./injection/db-adapters.js";
import { readGitVersion } from "./injection/git-injector-version.js";
import type { GitVersion } from "./injection/git-injector-version.js";
import type { McpConnectionEntry, McpConnectionRegistry } from "./injection/mcp-registry.js";
import { StdioChildTransport } from "./injection/mcp-stdio-transport.js";
import { spawnCaptured } from "./injection/spawn-captured.js";
import type { SpawnCapturedResult } from "./injection/spawn-captured.js";
import { SmtpInjector } from "./injection/smtp-injector.js";
import type { SmtpInjectorDeps } from "./injection/smtp-injector.js";
import { EphemeralSshAgent } from "./injection/ssh-agent/index.js";
import { validateHostPort, validateUrl } from "./injection/url-validator.js";
import type { ValidatedUrl } from "./injection/url-validator.js";
import { forceJobWrapperUnavailableForTests } from "./injection/win32-job-wrapper.js";
import type { SqliteStore } from "./storage/sqlite-store.js";
import { VaultEngine } from "./vault-engine.js";

vi.mock("./crypto/argon2.js", async (importOriginal) =>
  (await import("./__fixtures__/argon2-stub.js")).argon2Stub(importOriginal),
);
vi.mock("./injection/spawn-captured.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./injection/spawn-captured.js")>();
  return { ...actual, spawnCaptured: vi.fn() };
});
vi.mock("./injection/git-injector-version.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./injection/git-injector-version.js")>();
  return { ...actual, readGitVersion: vi.fn() };
});
vi.mock("./injection/url-validator.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./injection/url-validator.js")>();
  return {
    ...actual,
    validateUrl: vi.fn(actual.validateUrl),
    validateHostPort: vi.fn(actual.validateHostPort),
  };
});
vi.mock("./injection/ssh-agent/index.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./injection/ssh-agent/index.js")>();
  return { ...actual, EphemeralSshAgent: { start: vi.fn() } };
});
vi.mock("node:dns", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:dns")>();
  return { ...actual, promises: { ...actual.promises, lookup: vi.fn() } };
});

const PW_FIXTURE = "pw-fixture-r7v3";
const DOCKER_USER = "bob";
const VALUE_HANDLE = "mcpvalue";
const VALUE_URL = "urlvalue";
const VALUE_MODE = "modevalue";
const WORD_SERVER = "server";
const PAIR_SE = "se";
const WORD_CONFIG = "config";
const WORD_CONTEXT = "context";
const WORD_ATTACHMENT = "attachment";

const GIT = resolveSupportedGit();
const spawnMock = vi.mocked(spawnCaptured);
const gitVersionMock = vi.mocked(readGitVersion);
const validateUrlMock = vi.mocked(validateUrl);
const validateHostPortMock = vi.mocked(validateHostPort);
const agentStartMock = vi.mocked(EphemeralSshAgent.start);
const dnsLookupMock = dnsPromises.lookup as unknown as Mock<
  (hostname: string, options?: unknown) => Promise<unknown>
>;

const SUPPORTED_GIT: GitVersion = { major: 2, minor: 45, patch: 0 };
const FAKE_AGENT = {
  authSock: "harpoc-use-error-text-agent",
  publicKeyOpenssh: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA harpoc",
  dispose: () => undefined,
} as unknown as EphemeralSshAgent;
const TEMP_NAMES = ["TEMP", "TMP", "TMPDIR"] as const;

let tempDir: string;
let workDir: string;
let engine: VaultEngine;
let savedPath: string | undefined;
let savedTemp: Record<(typeof TEMP_NAMES)[number], string | undefined>;

beforeEach(async () => {
  tempDir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-use-error-text-")));
  workDir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-use-error-work-")));
  engine = new VaultEngine({
    dbPath: join(tempDir, "test.vault.db"),
    sessionPath: join(tempDir, "session.json"),
  });
  await engine.initVault("password");
  savedPath = process.env.PATH;
  savedTemp = { TEMP: process.env.TEMP, TMP: process.env.TMP, TMPDIR: process.env.TMPDIR };
  spawnMock.mockReset();
  gitVersionMock.mockReset();
  gitVersionMock.mockResolvedValue(SUPPORTED_GIT);
  validateUrlMock.mockReset();
  validateHostPortMock.mockReset();
  agentStartMock.mockReset();
  agentStartMock.mockResolvedValue(FAKE_AGENT);
  dnsLookupMock.mockReset();
});

afterEach(async () => {
  for (const name of TEMP_NAMES) {
    const saved = savedTemp[name];
    if (saved === undefined) Reflect.deleteProperty(process.env, name);
    else process.env[name] = saved;
  }
  spawnMock.mockReset();
  if (savedPath === undefined) delete process.env.PATH;
  else process.env.PATH = savedPath;
  await engine.destroy();
  rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  rmSync(workDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

async function storeSecret(name: string, value: string): Promise<string> {
  await engine.createSecret({ name, type: "api_key", value: new Uint8Array(Buffer.from(value)) });
  return `secret://${name}`;
}

function installPostgresAdapter(adapter: DbEngineAdapter): void {
  const internals = engine as unknown as {
    auditLogger: AuditLogger;
    databaseInjector: DatabaseInjector;
  };
  internals.databaseInjector = new DatabaseInjector(internals.auditLogger, {
    postgresql: adapter,
  });
}

function databaseAction(): DatabaseAction {
  return {
    type: "database",
    engine: "postgresql",
    host: "8.8.8.8",
    database: "app",
    query: "SELECT 1",
  };
}

describe("an unrecorded error is searched for a split-off password", () => {
  it.skipIf(GIT === null)(
    "git over https: the spawn seam's error (skipped where no supported git resolves)",
    async () => {
      const handle = await storeSecret("git", `user:${PW_FIXTURE}`);
      await engine.setInjectionPolicy(handle, {
        command_allowlist: [GIT as string],
        url_allowlist: ["https://127.0.0.1:1/*"],
      });
      const retained = retainDecryptedValues(engine);
      spawnMock.mockRejectedValue(
        new VaultError(ErrorCode.GIT_OPERATION_FAILED, `remote said ${PW_FIXTURE}`),
      );
      const action: GitAction = {
        type: "git",
        operation: "ls-remote",
        repository: "https://127.0.0.1:1/harpoc/text.git",
      };

      const err = await expectVaultError(
        () => engine.useSecret(handle, action),
        ErrorCode.GIT_OPERATION_FAILED,
      );

      expectAbsent(err.message, PW_FIXTURE);
      expect(err.message).toBe("remote said [REDACTED]");
      expect(retained).toHaveLength(1);
    },
  );

  it("the database context: the driver seam's error", async () => {
    const handle = await storeSecret("db", `user:${PW_FIXTURE}`);
    await engine.setInjectionPolicy(handle, { host_allowlist: ["8.8.8.8"] });
    installPostgresAdapter(
      new MockAdapter({
        connectError: new VaultError(ErrorCode.VAULT_LOCKED, `remote said ${PW_FIXTURE}`),
      }),
    );
    const retained = retainDecryptedValues(engine);

    const err = await expectVaultError(
      () => engine.useSecret(handle, databaseAction()),
      ErrorCode.VAULT_LOCKED,
    );

    expectAbsent(err.message, PW_FIXTURE);
    expect(err.message).toBe("remote said [REDACTED]");
    expect(retained).toHaveLength(1);
  });

  it("docker: the spawn seam's error, with the password and with the user alone", async () => {
    const binDir = join(tempDir, "bin");
    const dockerPath = join(binDir, process.platform === "win32" ? "docker.exe" : "docker");
    mkdirSync(binDir);
    writeFileSync(dockerPath, "", { mode: 0o755 });
    process.env.PATH = binDir + delimiter + (savedPath ?? "");
    const handle = await storeSecret("registry", `${DOCKER_USER}:${PW_FIXTURE}`);
    await engine.setInjectionPolicy(handle, {
      host_allowlist: ["registry.example.com"],
      command_allowlist: [dockerPath],
    });
    const retained = retainDecryptedValues(engine);
    const action: DockerRegistryAction = {
      type: "docker_registry",
      operation: "pull",
      image: "registry.example.com/app:1.0",
      timeout_ms: 300_000,
    };

    for (const needle of [PW_FIXTURE, DOCKER_USER]) {
      spawnMock.mockRejectedValue(
        new VaultError(ErrorCode.DOCKER_OPERATION_FAILED, `remote said ${needle}`),
      );

      const err = await expectVaultError(
        () => engine.useSecret(handle, action),
        ErrorCode.DOCKER_OPERATION_FAILED,
      );

      expectAbsent(err.message, needle);
      expect(err.message).toBe("remote said [REDACTED]");
    }
    expect(retained).toHaveLength(2);
  });
});

describe("the choke point writes a recorded error from the action as copied at the door", () => {
  it("a seam's recorded error reads the host the call sent, not the caller's object changed after the door", async () => {
    const handle = await storeSecret("db", `user:${PW_FIXTURE}`);
    await engine.setInjectionPolicy(handle, { host_allowlist: ["8.8.8.8"] });
    const action = databaseAction();
    installPostgresAdapter({
      connect: () => {
        action.host = "changed.example";
        return Promise.reject(
          new VaultError(ErrorCode.VAULT_LOCKED, vaultText`host ${echoField({}, "host")}`),
        );
      },
    });

    const err = await expectVaultError(
      () => engine.useSecret(handle, action),
      ErrorCode.VAULT_LOCKED,
    );

    expect(err.message).toBe("host 8.8.8.8");
  });
});

/** A stored configuration of `kind` holding `plaintext`, written past the engine's admin path (test seam — private fields). */
function storeConfigBlob(kind: "mcp" | "connection", secretId: string, plaintext: string): void {
  const { kek, store } = engine as unknown as { kek: Uint8Array; store: SqliteStore };
  const aad = kind === "mcp" ? AAD_MCP_SERVER_CONFIG(secretId) : AAD_CONNECTION_CONFIG(secretId);
  const enc = encrypt(kek, new Uint8Array(Buffer.from(plaintext, "utf8")), aad);
  const now = Date.now();
  const row = {
    secret_id: secretId,
    config_encrypted: enc.ciphertext,
    config_iv: enc.iv,
    config_tag: enc.tag,
    created_at: now,
    updated_at: now,
  };
  if (kind === "mcp") store.upsertMcpServer(row);
  else store.upsertConnectionConfig(row);
}

function httpAction(url: string, extra: Record<string, unknown> = {}): HttpAction {
  return {
    type: "http",
    method: "GET",
    url,
    injection: { type: "bearer" },
    ...extra,
  } as HttpAction;
}

describe("the engine's own sites after the decrypt", () => {
  it("the MCP arm's refusal quotes the handle as sent", async () => {
    const handle = await storeSecret(VALUE_HANDLE, VALUE_HANDLE);

    const err = await expectVaultError(
      () => engine.useSecret(handle, { type: "mcp", server: "github-mcp", tool: "echo" }),
      ErrorCode.MCP_SERVER_NOT_CONFIGURED,
    );

    expect(err.message).toBe(`MCP server not configured for secret: secret://${VALUE_HANDLE}`);
  });

  it("the http arm's allowlist refusal quotes the URL as sent", async () => {
    const handle = await storeSecret("http", VALUE_URL);
    const url = `https://api.example.com/?q=${VALUE_URL}`;

    const err = await expectVaultError(
      () => engine.useSecret(handle, httpAction(url)),
      ErrorCode.URL_NOT_ALLOWED,
    );

    expect(err.message).toBe(`URL not in secret allowlist: ${url}`);
  });

  it("the http arm's response-mode refusal quotes the mode as sent and the policy's mode", async () => {
    const handle = await storeSecret("mode", VALUE_MODE);
    await engine.setInjectionPolicy(handle, { url_allowlist: ["https://api.example.com/*"] });

    const err = await expectVaultError(
      () =>
        engine.useSecret(
          handle,
          httpAction("https://api.example.com/x", { response_mode: VALUE_MODE }),
        ),
      ErrorCode.RESPONSE_MODE_NOT_ALLOWED,
    );

    expect(err.message).toBe(
      `Response mode "${VALUE_MODE}" not allowed: secret policy is "filtered" and overrides may only tighten`,
    );
  });

  it("a stored MCP server config that does not parse: its paths redacted, the words around them as they stand", async () => {
    const handle = await storeSecret("srv", WORD_SERVER);
    const secretId = await engine.resolveSecretId(handle);
    storeConfigBlob(
      "mcp",
      secretId,
      JSON.stringify({ server_name: 5, transport: "http", url: "https://x.example/mcp" }),
    );

    const err = await expectVaultError(
      () => engine.useSecret(handle, { type: "mcp", server: "github-mcp", tool: "echo" }),
      ErrorCode.VAULT_CORRUPTED,
    );

    expect(err.message).toBe(
      `Vault corrupted: MCP server config for secret ${secretId} is malformed ([REDACTED]_name)`,
    );
  });

  it("a stored MCP server config that is not JSON: the words as they stand", async () => {
    const handle = await storeSecret("srv", WORD_SERVER);
    const secretId = await engine.resolveSecretId(handle);
    storeConfigBlob("mcp", secretId, "not json");

    const err = await expectVaultError(
      () => engine.useSecret(handle, { type: "mcp", server: "github-mcp", tool: "echo" }),
      ErrorCode.VAULT_CORRUPTED,
    );

    expect(err.message).toBe(
      `Vault corrupted: MCP server config for secret ${secretId} is not JSON`,
    );
  });

  it("a stored connection config that does not parse: its paths redacted, the words around them as they stand", async () => {
    const handle = await storeSecret("conn", PAIR_SE);
    const secretId = await engine.resolveSecretId(handle);
    await engine.setInjectionPolicy(handle, { url_allowlist: ["https://api.example.com/*"] });
    storeConfigBlob("connection", secretId, JSON.stringify({ database: { tls_mode: 5 } }));

    const err = await expectVaultError(
      () => engine.useSecret(handle, httpAction("https://api.example.com/x")),
      ErrorCode.VAULT_CORRUPTED,
    );

    expect(err.message.startsWith("Vault corrupted: Connection config for secret ")).toBe(true);
    expect(err.message.endsWith(" is malformed (databa[REDACTED].tls_mode)")).toBe(true);
  });

  it("a stored connection config that is not JSON: the words as they stand", async () => {
    const handle = await storeSecret("conn", WORD_CONFIG);
    const secretId = await engine.resolveSecretId(handle);
    await engine.setInjectionPolicy(handle, { url_allowlist: ["https://api.example.com/*"] });
    storeConfigBlob("connection", secretId, "not json");

    const err = await expectVaultError(
      () => engine.useSecret(handle, httpAction("https://api.example.com/x")),
      ErrorCode.VAULT_CORRUPTED,
    );

    expect(err.message).toBe(
      `Vault corrupted: Connection config for secret ${secretId} is not JSON`,
    );
  });

  it("a raw throw of an injector: the fixed words as they stand", async () => {
    const handle = await storeSecret("raw", WORD_CONTEXT);
    await engine.setInjectionPolicy(handle, { url_allowlist: ["https://api.example.com/*"] });
    (engine as unknown as { httpInjector: unknown }).httpInjector = {
      executeWithSecret: () => Promise.reject(new Error("the injector broke")),
    };

    const err = await expectVaultError(
      () => engine.useSecret(handle, httpAction("https://api.example.com/x")),
      ErrorCode.INTERNAL_ERROR,
    );

    expect(err.message).toBe("the injection context failed unexpectedly");
  });

  it("an attachment the smtp context cannot read: the fixed words as they stand", async () => {
    const handle = await storeSecret("mail", WORD_ATTACHMENT);
    (engine as unknown as { smtpInjector: unknown }).smtpInjector = {
      run: () => Promise.reject(Object.assign(new Error("ENOENT: injected"), { code: "ENOENT" })),
    };
    const action = {
      type: "smtp",
      host: "smtp.example.com",
      security: "tls",
      from: "a@example.com",
      to: ["b@example.com"],
      subject: "s",
      text: "t",
    } as SmtpAction;

    const err = await expectVaultError(
      () => engine.useSecret(handle, action),
      ErrorCode.FILE_IO_ERROR,
    );

    expect(err.message).toBe("an attachment could not be read");
  });
});

const SSH_HOST = "ssh.example";
const KNOWN_HOST = `${SSH_HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA`;
const HOST_KEY_FAILURE = "Host key verification failed.\r\n";
const MSYS_TEXT_TAIL =
  " is an MSYS/Cygwin build (msys-2.0.dll or cygwin1.dll beside it), which cannot reach the vault's named-pipe ssh-agent; allowlist the native Win32-OpenSSH client (C:\\Windows\\System32\\OpenSSH\\ssh.exe) and put its directory ahead of Git's usr\\bin on PATH";
const UNRESOLVED_TEXT = "Git operation failed: could not resolve the working tree's repository";
const OWN_CONFIGURATION_TEXT =
  "working_directory's repository configures a program or an address rewrite of its own";

const VALUE_COMMAND = "cmdvalue";
const VALUE_TOOL = "valuetool";
const VALUE_TRANSPORT = "valuetransport";
const VALUE_POSITIONAL = "positionalvalue";
const VALUE_SPEC = "valuespec";
const VALUE_NEGATIVE_SPEC = "^refs/heads/valuebranch";
const VALUE_REPO = "valuerepo";
const VALUE_HOST = "valuehost";
const VALUE_REGISTRY = "valuereg";
const WORD_ALLOWLIST = "allowlist";
const WORD_DEDICATED = "dedicated";
const WORD_DIRECTORY = "directory";
const WORD_EXIST = "exist";
const WORD_WHITESPACE = "whitespace";
const WORD_OPERATION = "operation";
const WORD_DISALLOWED = "disallowed";
const WORD_ACCEPTED = "accepted";
const WORD_EMPTY = "empty";
const WORD_START = "start";
const WORD_REPOSITORY = "repository";
const WORD_BEGIN = "begin";
const WORD_VERSION = "version";
const WORD_OLDER = "older";
const WORD_JUDGED = "judged";
const WORD_WINDOWS = "Windows";
const WORD_TEMPORARY = "temporary";
const WORD_DAEMON = "daemon";
const WORD_REQUIRED = "required";
const WORD_NAMES = "names";
const WORD_DERIVE = "derive";
const WORD_SHARE = "share";
const WORD_SEGMENT = "segment";
const WORD_HOLD = "hold";
const WORD_SERVES = "serves";
const WORD_RESOLVE = "resolve";
const WORD_CAP = "cap";
const WORD_EXCEEDS = "exceeds";
const WORD_PREPARED = "prepared";
const WORD_OUTSIDE = "outside";
const WORD_LISTED = "listed";
const WORD_PROGRAM = "program";
const WORD_REWRITE = "rewrite";
const WORD_PARSE = "parse";
const WORD_LITERAL = "literal";
const WORD_LETTERS = "letters";
const WORD_CARRY = "carry";
const WORD_DIGIT = "digit";
const WORD_CONTROLLED = "controlled";
const WORD_BINARY = "binary";
const WORD_PARSED = "parsed";
const WORD_MERGE = "merge";
const WORD_CHARACTER = "character";
const WORD_NEWLINES = "newlines";
const WORD_BACKSLASH = "backslash";
const WORD_BATCH = "batch";
const WORD_ABSOLUTE = "absolute";
const WORD_DEVICE = "device";
const WORD_GLOB = "glob";
const WORD_FILE = "file";
const WORD_REFERENCE = "reference";
const WORD_DOCKER = "docker";

/** An empty file the command allowlist resolves as `name`, its directory put first on PATH. */
function installBinary(name: string, dir = join(tempDir, "bin")): string {
  mkdirSync(dir, { recursive: true });
  const path = join(dir, process.platform === "win32" ? `${name}.exe` : name);
  writeFileSync(path, "", { mode: 0o755 });
  process.env.PATH = dir + delimiter + (process.env.PATH ?? "");
  return path;
}

/** An ssh or sftp client resolved under `<tempDir>/binary`, an MSYS runtime beside it. */
function installMsysClient(name: string): string {
  const dir = join(tempDir, WORD_BINARY);
  const path = installBinary(name, dir);
  writeFileSync(join(dir, "msys-2.0.dll"), "");
  return path;
}

function msysText(): string {
  return `Unsupported ssh client: the binary resolved under ${join(tempDir, "[REDACTED]")}${MSYS_TEXT_TAIL}`;
}

function spawned(over: Partial<SpawnCapturedResult> = {}): SpawnCapturedResult {
  return {
    exit_code: 0,
    stdout: "",
    stderr: "",
    timed_out: false,
    truncated: false,
    signal: null,
    spawn_failed: false,
    redacted: false,
    ...over,
  };
}

async function refusedText(handle: string, action: unknown, code: ErrorCode): Promise<string> {
  const err = await expectVaultError(
    () => engine.useSecret(handle, action as UseSecretAction),
    code,
  );
  return err.message;
}

function breakTempDir(): void {
  const missing = join(workDir, "no-such-directory");
  for (const name of TEMP_NAMES) process.env[name] = missing;
}

describe("the process context's sites", () => {
  function processAction(command: string, extra: Record<string, unknown> = {}): UseSecretAction {
    return { type: "process", command, env_var: "HARPOC_TOKEN", ...extra } as UseSecretAction;
  }

  it("an empty command allowlist quotes the command as sent", async () => {
    const handle = await storeSecret("proc", VALUE_COMMAND);

    const text = await refusedText(
      handle,
      processAction(VALUE_COMMAND),
      ErrorCode.COMMAND_NOT_ALLOWED,
    );

    expect(text).toBe(`Command not in secret allowlist: ${VALUE_COMMAND}`);
  });

  it("a command that resolves to no file quotes the command as sent", async () => {
    const tool = installBinary("tool");
    const handle = await storeSecret("proc", VALUE_COMMAND);
    await engine.setInjectionPolicy(handle, { command_allowlist: [tool] });

    const text = await refusedText(
      handle,
      processAction(VALUE_COMMAND),
      ErrorCode.COMMAND_NOT_ALLOWED,
    );

    expect(text).toBe(`Command not in secret allowlist: ${VALUE_COMMAND}`);
  });

  it("a command that matches no entry quotes the command as sent", async () => {
    const tool = installBinary("tool");
    const command = installBinary(VALUE_TOOL);
    const handle = await storeSecret("proc", VALUE_TOOL);
    await engine.setInjectionPolicy(handle, { command_allowlist: [tool] });

    const text = await refusedText(handle, processAction(command), ErrorCode.COMMAND_NOT_ALLOWED);

    expect(text).toBe(`Command not in secret allowlist: ${command}`);
  });

  it("a binary with a dedicated context: the binary's and the context's names as tokens", async () => {
    const git = installBinary("git");
    const handle = await storeSecret("proc", WORD_DEDICATED);
    await engine.setInjectionPolicy(handle, { command_allowlist: [git] });

    const text = await refusedText(
      handle,
      processAction(git),
      ErrorCode.DEDICATED_CONTEXT_REQUIRED,
    );

    expect(text).toBe(
      "'git' has a dedicated injection context and cannot be run through the process context: its command allowlist entry exists so the 'git' context can spawn it under vault-authored arguments. Use action.type 'git' instead",
    );
  });

  it("a working directory that is a file: the fixed words as they stand", async () => {
    const tool = installBinary("tool");
    const file = join(workDir, "file.txt");
    writeFileSync(file, "");
    const handle = await storeSecret("proc", WORD_DIRECTORY);
    await engine.setInjectionPolicy(handle, { command_allowlist: [tool] });

    const text = await refusedText(
      handle,
      processAction(tool, { working_directory: file }),
      ErrorCode.INVALID_PROCESS_CONFIG,
    );

    expect(text).toBe("working_directory is not a directory");
  });

  it("a working directory that does not exist: the fixed words as they stand", async () => {
    const tool = installBinary("tool");
    const handle = await storeSecret("proc", WORD_EXIST);
    await engine.setInjectionPolicy(handle, { command_allowlist: [tool] });

    const text = await refusedText(
      handle,
      processAction(tool, { working_directory: join(workDir, "missing") }),
      ErrorCode.INVALID_PROCESS_CONFIG,
    );

    expect(text).toBe("working_directory does not exist");
  });

  it("the MCP context's stored launch command is outside text: redacted, the words around it as they stand", async () => {
    const handle = await storeSecret("srv", WORD_ALLOWLIST);
    await engine.setMcpServerConfig(handle, {
      server_name: "srv",
      transport: "stdio",
      command: WORD_ALLOWLIST,
      env_var: "HARPOC_TOKEN",
    });

    const text = await refusedText(
      handle,
      { type: "mcp", server: "srv", tool: "echo" },
      ErrorCode.COMMAND_NOT_ALLOWED,
    );

    expect(text).toBe("Command not in secret allowlist: [REDACTED]");
  });
});

type GitStep =
  "probe" | "toplevel" | "symbolic" | "remotes" | "refs" | "network" | "listing" | "local";
type GitAnswer =
  Partial<SpawnCapturedResult> | ((cwd: string | undefined) => Partial<SpawnCapturedResult>);
interface WorkTree {
  top: string;
  gitDir: string;
}

function gitStepOf(args: readonly string[]): GitStep {
  if (args.some((arg) => arg.startsWith("--git-dir="))) return "network";
  if (args.includes("--absolute-git-dir")) return "probe";
  if (args.includes("--show-toplevel")) return "toplevel";
  if (args.includes("symbolic-ref")) return "symbolic";
  if (args.includes("--fixed-value")) return "remotes";
  if (args.includes("for-each-ref")) return "refs";
  if (args.includes("--get-regexp")) return "listing";
  return "local";
}

/** A repository the git context serves, outside the vault's directory. */
function workTree(): WorkTree {
  const top = join(workDir, "work");
  const gitDir = join(top, ".git");
  mkdirSync(join(gitDir, "objects"), { recursive: true });
  mkdirSync(join(gitDir, "refs"), { recursive: true });
  writeFileSync(join(gitDir, "HEAD"), "ref: refs/heads/main\n");
  return { top, gitDir };
}

function probeAnswer(
  tree: WorkTree,
  over: { format?: string; gitDir?: string; bare?: string } = {},
): string {
  return [
    join(tree.gitDir, "objects"),
    join(tree.gitDir, "shallow"),
    over.format ?? "sha1",
    over.gitDir ?? tree.gitDir,
    tree.gitDir,
    over.bare ?? "false",
  ].join("\n");
}

/** Scripts every git step of a relayed operation: each answers as a served repository does, but where `over` says otherwise. */
function answerGitSteps(tree: WorkTree, over: Partial<Record<GitStep, GitAnswer>> = {}): void {
  const answers: Record<GitStep, GitAnswer> = {
    probe: { stdout: `${probeAnswer(tree)}\n` },
    toplevel: { stdout: `${tree.top}\n` },
    symbolic: { stdout: "refs/heads/main\n" },
    remotes: { stdout: "remote.origin.url\0" },
    refs: { stdout: "" },
    network: {},
    listing: { exit_code: 1 },
    local: {},
    ...over,
  };
  spawnMock.mockImplementation((_command, args, opts) => {
    const answer = answers[gitStepOf(args)];
    return Promise.resolve(spawned(typeof answer === "function" ? answer(opts.cwd) : answer));
  });
}

const VALUE_ADDRESS = "10.20.30.40";

function lookupNotFound(): Error {
  return Object.assign(new Error("getaddrinfo ENOTFOUND"), { code: "ENOTFOUND" });
}

describe("the git context's sites", () => {
  const HTTPS_REPOSITORY = "https://8.8.8.8/org/repo.git";
  const SSH_REPOSITORY = `git@${SSH_HOST}:org/repo.git`;

  async function gitSecret(value: string, policy: InjectionPolicyInput = {}): Promise<string> {
    const git = installBinary("git");
    const handle = await storeSecret("git", value);
    await engine.setInjectionPolicy(handle, {
      command_allowlist: [git],
      url_allowlist: ["https://8.8.8.8/*", "https://git.example/*"],
      host_allowlist: [SSH_HOST],
      ...policy,
    });
    await engine.setConnectionConfig(handle, { ssh: { known_hosts: [KNOWN_HOST] } });
    return handle;
  }

  function gitAction(extra: Record<string, unknown>): UseSecretAction {
    return {
      type: "git",
      operation: "ls-remote",
      repository: HTTPS_REPOSITORY,
      ...extra,
    } as UseSecretAction;
  }

  async function gitText(
    value: string,
    extra: Record<string, unknown>,
    code: ErrorCode,
    policy: InjectionPolicyInput = {},
  ): Promise<string> {
    const handle = await gitSecret(value, policy);
    return refusedText(handle, gitAction(extra), code);
  }

  const INPUT_ROWS: [
    string,
    string,
    Record<string, unknown>,
    ErrorCode,
    string,
    InjectionPolicyInput?,
  ][] = [
    [
      "a repository that is no string",
      WORD_WHITESPACE,
      { repository: 5 },
      ErrorCode.INVALID_GIT_CONFIG,
      "repository must be a string without leading or trailing whitespace",
    ],
    [
      "a repository of no transport quotes it as sent",
      VALUE_TRANSPORT,
      { repository: VALUE_TRANSPORT },
      ErrorCode.GIT_UNSUPPORTED_TRANSPORT,
      `Unsupported git transport for repository: ${VALUE_TRANSPORT}`,
    ],
    [
      "an operation the context does not know",
      WORD_OPERATION,
      { operation: "nope" },
      ErrorCode.INVALID_GIT_CONFIG,
      "unsupported git operation",
    ],
    [
      "a denied argument names the table's entry",
      WORD_DISALLOWED,
      { operation: "clone", args: ["--upload-pack=x"] },
      ErrorCode.INVALID_GIT_CONFIG,
      "disallowed git argument: --upload-pack",
    ],
    [
      "a positional argument quotes it as sent",
      VALUE_POSITIONAL,
      { operation: "push", args: [VALUE_POSITIONAL] },
      ErrorCode.INVALID_GIT_CONFIG,
      `a push takes no positional argument: ${VALUE_POSITIONAL}`,
    ],
    [
      "refspecs on another operation than a fetch",
      WORD_ACCEPTED,
      { operation: "clone", refspecs: ["refs/heads/main"] },
      ErrorCode.INVALID_GIT_CONFIG,
      "refspecs is only accepted by a fetch",
    ],
    [
      "an empty refspec list",
      WORD_EMPTY,
      { operation: "fetch", refspecs: [] },
      ErrorCode.INVALID_GIT_CONFIG,
      "refspecs must not be empty",
    ],
    [
      "a refspec the context refuses quotes it as sent",
      VALUE_SPEC,
      { operation: "fetch", refspecs: ["refs/heads/main", VALUE_SPEC] },
      ErrorCode.INVALID_GIT_CONFIG,
      `unsupported fetch refspec: ${VALUE_SPEC}`,
    ],
    [
      "a refspec list is quoted element by element with the value as one of them",
      VALUE_NEGATIVE_SPEC,
      { operation: "fetch", refspecs: ["^refs/heads/main", VALUE_NEGATIVE_SPEC] },
      ErrorCode.INVALID_GIT_CONFIG,
      `a fetch needs a refspec that is not negative: ^refs/heads/main, ${VALUE_NEGATIVE_SPEC}`,
    ],
    [
      "a working directory led by a dash",
      WORD_START,
      { operation: "clone", working_directory: "-wd" },
      ErrorCode.INVALID_GIT_CONFIG,
      "working_directory must not start with '-'",
    ],
    [
      "a repository led by a dash",
      WORD_REPOSITORY,
      { operation: "clone", repository: `-x@${SSH_HOST}:org/repo.git` },
      ErrorCode.INVALID_GIT_CONFIG,
      "repository must not start with '-'",
    ],
    [
      "git is not on the command allowlist: the binary's name as words",
      WORD_ALLOWLIST,
      {},
      ErrorCode.COMMAND_NOT_ALLOWED,
      "Command not in secret allowlist: git",
      { command_allowlist: [] },
    ],
    [
      "an HTTPS host led by a sign",
      WORD_BEGIN,
      { repository: "https://-x.example/org/repo.git" },
      ErrorCode.INVALID_GIT_CONFIG,
      "HTTPS host of the repository must not begin with '-' or '+'",
    ],
    [
      "a repository off the URL allowlist quotes it as sent",
      VALUE_REPO,
      { repository: `https://8.8.8.8/org/${VALUE_REPO}.git` },
      ErrorCode.URL_NOT_ALLOWED,
      `URL not in secret allowlist: https://8.8.8.8/org/${VALUE_REPO}.git`,
      { url_allowlist: ["https://9.9.9.9/*"] },
    ],
    [
      "an ls-remote with a working directory",
      WORD_ACCEPTED,
      { working_directory: "wd" },
      ErrorCode.INVALID_GIT_CONFIG,
      "working_directory is not accepted by ls-remote",
    ],
    [
      "a pull without a working directory: the operation as a token",
      WORD_REQUIRED,
      { operation: "pull" },
      ErrorCode.INVALID_GIT_CONFIG,
      "working_directory is required for pull",
    ],
    [
      "a clone address that names no directory",
      WORD_NAMES,
      { operation: "clone", repository: "https://8.8.8.8/org/x:.git" },
      ErrorCode.INVALID_GIT_CONFIG,
      "a clone without working_directory needs a repository address that names a directory",
    ],
    [
      "a clone address that derives a .git directory",
      WORD_DERIVE,
      { operation: "clone", repository: "https://8.8.8.8/org/.git.git" },
      ErrorCode.INVALID_GIT_CONFIG,
      "a clone without working_directory must not derive a .git directory from the repository",
    ],
    [
      "a working directory with a .git segment",
      WORD_HOLD,
      { operation: "clone", working_directory: `wd${sep}.git${sep}x` },
      ErrorCode.INVALID_GIT_CONFIG,
      "working_directory must not hold a .git segment",
    ],
    [
      "an ssh:// address without a host",
      WORD_PARSE,
      { repository: "ssh://" },
      ErrorCode.INVALID_GIT_CONFIG,
      "could not parse SSH host from repository",
    ],
    [
      "an SSH host that is no name",
      WORD_LITERAL,
      { repository: "git@ho!st:org/repo.git" },
      ErrorCode.INVALID_GIT_CONFIG,
      "SSH host of the repository must be a host name or an IPv6 literal",
    ],
    [
      "an SSH user that is no name",
      WORD_LETTERS,
      { repository: `us!er@${SSH_HOST}:org/repo.git` },
      ErrorCode.INVALID_GIT_CONFIG,
      "SSH user of the repository must be a name of letters, digits, '.', '_' and '-' that begins with a letter or a digit",
    ],
    [
      "an ssh:// address with a password",
      WORD_CARRY,
      { repository: `ssh://user:pw@${SSH_HOST}/org/repo.git` },
      ErrorCode.INVALID_GIT_CONFIG,
      "an SSH repository address must not carry a password",
    ],
    [
      "a userless ssh:// address holding an encoded @",
      WORD_DIGIT,
      { repository: `ssh://${SSH_HOST}/org%40repo.git` },
      ErrorCode.INVALID_GIT_CONFIG,
      "SSH user of the repository must be a name of letters, digits, '.', '_' and '-' that begins with a letter or a digit",
    ],
    [
      "git over ssh names the repository as sent: HOST_NOT_ALLOWED",
      VALUE_HOST,
      { repository: `git@${VALUE_HOST}:org/repo.git` },
      ErrorCode.HOST_NOT_ALLOWED,
      `Host not in secret allowlist: git@${VALUE_HOST}:org/repo.git`,
    ],
  ];

  it.each(INPUT_ROWS)("%s", async (_title, value, extra, code, message, policy) => {
    expect(await gitText(value, extra, code, policy)).toBe(message);
  });

  it("git over ssh names the repository as sent: SSH_HOST_KEY_MISMATCH", async () => {
    installBinary("ssh");
    spawnMock.mockResolvedValue(spawned({ exit_code: 255, stderr: HOST_KEY_FAILURE }));

    const text = await gitText(
      VALUE_HOST,
      { repository: `git@${VALUE_HOST}:org/repo.git` },
      ErrorCode.SSH_HOST_KEY_MISMATCH,
      { host_allowlist: [VALUE_HOST] },
    );

    expect(text).toBe(
      `SSH host key does not match the pinned key for: git@${VALUE_HOST}:org/repo.git`,
    );
  });

  it("no ssh binary on the controlled PATH", async () => {
    const handle = await gitSecret(WORD_CONTROLLED);
    process.env.PATH = join(tempDir, "bin");

    const text = await refusedText(
      handle,
      gitAction({ repository: SSH_REPOSITORY }),
      ErrorCode.INVALID_GIT_CONFIG,
    );

    expect(text).toBe("ssh binary not found on the controlled PATH");
  });

  it.runIf(process.platform === "win32")(
    "an MSYS ssh client: its directory is outside text, the words around it as they stand (win32 only)",
    async () => {
      installMsysClient("ssh");

      const text = await gitText(
        WORD_BINARY,
        { repository: SSH_REPOSITORY },
        ErrorCode.SSH_CLIENT_UNSUPPORTED,
      );

      expect(text).toBe(msysText());
    },
  );

  it("a git whose version cannot be read", async () => {
    gitVersionMock.mockResolvedValue(null);

    const text = await gitText(WORD_VERSION, {}, ErrorCode.GIT_OPERATION_FAILED);

    expect(text).toBe("Git operation failed: git's version could not be read");
  });

  it("a git below the context's floor: the version's digits as numbers", async () => {
    gitVersionMock.mockResolvedValue({ major: 2, minor: 30, patch: 1 });

    const text = await gitText(WORD_OLDER, {}, ErrorCode.GIT_OPERATION_FAILED);

    expect(text).toBe(
      "Git operation failed: git 2.30.1 is older than 2.32, which the git context needs",
    );
  });

  it("a git below the pin's floor for a resolved host", async () => {
    gitVersionMock.mockResolvedValue({ major: 2, minor: 36, patch: 0 });
    validateUrlMock.mockResolvedValueOnce({
      url: new URL("https://git.example/org/repo.git"),
      resolvedAddresses: ["8.8.8.8"],
    });

    const text = await gitText(
      WORD_JUDGED,
      { repository: "https://git.example/org/repo.git" },
      ErrorCode.GIT_OPERATION_FAILED,
    );

    expect(text).toBe(
      "Git operation failed: git 2.36.0 is older than 2.37 and would ignore the addresses the vault judged for the repository host",
    );
  });

  it.runIf(process.platform === "win32")(
    "a git below the Windows floor of a pull (win32 only)",
    async () => {
      gitVersionMock.mockResolvedValue({ major: 2, minor: 37, patch: 0 });

      const text = await gitText(
        WORD_WINDOWS,
        { operation: "pull", working_directory: workDir },
        ErrorCode.GIT_OPERATION_FAILED,
      );

      expect(text).toBe(
        "Git operation failed: git 2.37.0 is older than 2.37.1, which a pull, a push and a fetch need on Windows",
      );
    },
  );

  it("an IP version the judged addresses lack", async () => {
    validateUrlMock.mockResolvedValueOnce({
      url: new URL("https://git.example/org/repo.git"),
      resolvedAddresses: ["8.8.8.8"],
    });

    const text = await gitText(
      WORD_VERSION,
      { operation: "clone", repository: "https://git.example/org/repo.git", args: ["--ipv6"] },
      ErrorCode.INVALID_GIT_CONFIG,
    );

    expect(text).toBe("repository host has no address of the requested IP version");
  });

  it("a temporary directory the context cannot write", async () => {
    const handle = await gitSecret(WORD_TEMPORARY);
    breakTempDir();

    const text = await refusedText(handle, gitAction({}), ErrorCode.GIT_OPERATION_FAILED);

    expect(text).toBe(
      "Git operation failed: a temporary file of the git context could not be prepared",
    );
  });

  it("a clone without a working directory in a daemon", async () => {
    engine.declareDaemon({ protectedDirs: [], protectedFiles: [] });

    const text = await gitText(WORD_DAEMON, { operation: "clone" }, ErrorCode.INVALID_GIT_CONFIG);

    expect(text).toBe("working_directory is required for clone in a daemon");
  });

  it("a working directory with a .. segment in a daemon", async () => {
    engine.declareDaemon({ protectedDirs: [], protectedFiles: [] });

    const text = await gitText(
      WORD_SEGMENT,
      { operation: "clone", working_directory: `${workDir}${sep}a${sep}..${sep}b` },
      ErrorCode.INVALID_GIT_CONFIG,
    );

    expect(text).toBe("working_directory must not hold a .. segment");
  });

  it.runIf(process.platform === "win32")(
    "a working directory on a network share (win32 only)",
    async () => {
      const text = await gitText(
        WORD_SHARE,
        { operation: "clone", working_directory: "\\\\server\\share\\x" },
        ErrorCode.INVALID_GIT_CONFIG,
      );

      expect(text).toBe("working_directory names a network share");
    },
  );

  it("a working directory that is a file", async () => {
    const file = join(workDir, "file.txt");
    writeFileSync(file, "");

    const text = await gitText(
      WORD_DIRECTORY,
      { operation: "pull", working_directory: file },
      ErrorCode.INVALID_GIT_CONFIG,
    );

    expect(text).toBe("working_directory is not a directory");
  });

  it("a working directory that does not exist", async () => {
    const text = await gitText(
      WORD_EXIST,
      { operation: "pull", working_directory: join(workDir, "missing") },
      ErrorCode.INVALID_GIT_CONFIG,
    );

    expect(text).toBe("working_directory does not exist");
  });

  it("a working directory in no repository the vault serves", async () => {
    const top = join(workDir, "plain");
    mkdirSync(top);
    writeFileSync(join(top, ".git"), "not a gitfile");

    const text = await gitText(
      WORD_SERVES,
      { operation: "push", working_directory: top },
      ErrorCode.INVALID_GIT_CONFIG,
    );

    expect(text).toBe("working_directory is not in a repository the vault serves");
  });

  const RELAYED_ROWS: [
    string,
    string,
    Record<string, unknown>,
    (tree: WorkTree) => Partial<Record<GitStep, GitAnswer>>,
    ErrorCode,
    string,
  ][] = [
    [
      "the first probe fails",
      WORD_RESOLVE,
      { operation: "push" },
      () => ({ probe: { exit_code: 1 } }),
      ErrorCode.GIT_OPERATION_FAILED,
      UNRESOLVED_TEXT,
    ],
    [
      "the first probe answers a line short",
      WORD_RESOLVE,
      { operation: "push" },
      (tree) => ({ probe: { stdout: probeAnswer(tree).split("\n").slice(1).join("\n") } }),
      ErrorCode.GIT_OPERATION_FAILED,
      UNRESOLVED_TEXT,
    ],
    [
      "the first probe names another object format",
      WORD_RESOLVE,
      { operation: "push" },
      (tree) => ({ probe: { stdout: probeAnswer(tree, { format: "md5" }) } }),
      ErrorCode.GIT_OPERATION_FAILED,
      UNRESOLVED_TEXT,
    ],
    [
      "the first probe calls the repository bare",
      WORD_RESOLVE,
      { operation: "push" },
      (tree) => ({ probe: { stdout: probeAnswer(tree, { bare: "true" }) } }),
      ErrorCode.GIT_OPERATION_FAILED,
      UNRESOLVED_TEXT,
    ],
    [
      "the first probe names another git directory",
      WORD_RESOLVE,
      { operation: "push" },
      (tree) => ({ probe: { stdout: probeAnswer(tree, { gitDir: join(workDir, "other") }) } }),
      ErrorCode.GIT_OPERATION_FAILED,
      UNRESOLVED_TEXT,
    ],
    [
      "a pull's top-level probe fails",
      WORD_RESOLVE,
      { operation: "pull" },
      () => ({ toplevel: { exit_code: 1 } }),
      ErrorCode.GIT_OPERATION_FAILED,
      UNRESOLVED_TEXT,
    ],
    [
      "a pull's top level is another directory",
      WORD_RESOLVE,
      { operation: "pull" },
      () => ({ toplevel: { stdout: `${workDir}\n` } }),
      ErrorCode.GIT_OPERATION_FAILED,
      UNRESOLVED_TEXT,
    ],
    [
      "a fetch's remote listing is cut",
      WORD_CAP,
      { operation: "fetch" },
      () => ({ remotes: { truncated: true } }),
      ErrorCode.GIT_OPERATION_FAILED,
      "Git operation failed: the working tree's remote listing exceeds the output cap",
    ],
    [
      "no remote has the URL: the repository as sent",
      VALUE_REPO,
      { operation: "fetch", repository: `https://8.8.8.8/org/${VALUE_REPO}.git` },
      () => ({ remotes: { exit_code: 1 } }),
      ErrorCode.INVALID_GIT_CONFIG,
      `no remote of the working tree has the URL https://8.8.8.8/org/${VALUE_REPO}.git`,
    ],
    [
      "two remotes have the URL: the count as a number, the repository as sent",
      VALUE_REPO,
      { operation: "fetch", repository: `https://8.8.8.8/org/${VALUE_REPO}.git` },
      () => ({ remotes: { stdout: "remote.a.url\0remote.b.url\0" } }),
      ErrorCode.INVALID_GIT_CONFIG,
      `2 remotes of the working tree have the URL https://8.8.8.8/org/${VALUE_REPO}.git`,
    ],
    [
      "the remote is no plain ref name: the repository as sent",
      VALUE_REPO,
      { operation: "fetch", repository: `https://8.8.8.8/org/${VALUE_REPO}.git` },
      () => ({ remotes: { stdout: "remote.a..b.url\0" } }),
      ErrorCode.INVALID_GIT_CONFIG,
      `the working tree's remote for https://8.8.8.8/org/${VALUE_REPO}.git is not a plain ref name`,
    ],
    [
      "the ref listing is cut",
      WORD_EXCEEDS,
      { operation: "push" },
      () => ({ refs: { truncated: true } }),
      ErrorCode.GIT_OPERATION_FAILED,
      "Git operation failed: the working tree's ref listing exceeds the output cap",
    ],
    [
      "the relay cannot be prepared",
      WORD_PREPARED,
      { operation: "push" },
      () => ({
        refs: () => {
          breakTempDir();
          return {};
        },
      }),
      ErrorCode.GIT_OPERATION_FAILED,
      "Git operation failed: the relay repository could not be prepared",
    ],
    [
      "the configuration listing fails",
      WORD_LISTED,
      { operation: "fetch" },
      () => ({ listing: { exit_code: 2 } }),
      ErrorCode.GIT_OPERATION_FAILED,
      "Git operation failed: the repository's configuration could not be listed",
    ],
    [
      "the repository configures a hook",
      WORD_PROGRAM,
      { operation: "fetch" },
      () => ({ listing: { exit_code: 0, stdout: "hook.x.command\0" } }),
      ErrorCode.INVALID_GIT_CONFIG,
      OWN_CONFIGURATION_TEXT,
    ],
  ];

  it.each(RELAYED_ROWS)("%s", async (_title, value, extra, over, code, message) => {
    const tree = workTree();
    answerGitSteps(tree, over(tree));

    const text = await gitText(value, { working_directory: tree.top, ...extra }, code);

    expect(text).toBe(message);
  });

  it("the relay changes outside the vault", async () => {
    answerGitSteps(workTree(), {
      network: (cwd) => {
        writeFileSync(join(cwd as string, "commondir"), "elsewhere\n");
        return {};
      },
    });

    const text = await gitText(WORD_OUTSIDE, {}, ErrorCode.GIT_OPERATION_FAILED);

    expect(text).toBe("Git operation failed: the relay repository changed outside the vault");
  });

  it("a legacy remote file named like the address in a daemon", async () => {
    installBinary("ssh");
    engine.declareDaemon({ protectedDirs: [], protectedFiles: [] });
    const repository = `git@${SSH_HOST}:repo`;
    const tree = workTree();
    mkdirSync(join(tree.gitDir, "remotes"));
    writeFileSync(join(tree.gitDir, "remotes", repository), "");
    answerGitSteps(tree);

    const text = await gitText(
      WORD_REWRITE,
      { operation: "fetch", repository, working_directory: tree.top },
      ErrorCode.INVALID_GIT_CONFIG,
    );

    expect(text).toBe(OWN_CONFIGURATION_TEXT);
  });

  it("an HTTPS repository that does not parse: the repository as sent", async () => {
    const repository = `https://[${VALUE_REPO}]/org/repo.git`;

    const text = await gitText(VALUE_REPO, { repository }, ErrorCode.URL_INVALID);

    expect(text).toBe(`Invalid URL: ${repository}`);
  });

  it("an HTTPS repository the lookup fails for: the repository as sent, the code as a token", async () => {
    const repository = `https://${VALUE_REPO}.example/org/repo.git`;
    dnsLookupMock.mockRejectedValueOnce(lookupNotFound());

    const text = await gitText(VALUE_REPO, { repository }, ErrorCode.DNS_RESOLUTION_FAILED);

    expect(text).toBe(`DNS resolution failed for ${repository}: ENOTFOUND`);
  });

  it("an HTTPS repository the DNS answers with the value: the repository as sent, the answer redacted there", async () => {
    const repository = "https://git.example/org/repo.git";
    dnsLookupMock.mockResolvedValueOnce([{ address: VALUE_ADDRESS, family: 4 }]);

    const text = await gitText(VALUE_ADDRESS, { repository }, ErrorCode.SSRF_BLOCKED);

    expectAbsent(text, VALUE_ADDRESS);
    expect(text).toBe(`SSRF blocked: ${repository} resolves to private IP [REDACTED]`);
  });
});

describe("the ssh context's sites", () => {
  async function sshSecret(value: string, policy: InjectionPolicyInput = {}): Promise<string> {
    const ssh = installBinary("ssh");
    const handle = await storeSecret("ssh", value);
    await engine.setInjectionPolicy(handle, {
      command_allowlist: [ssh],
      host_allowlist: [SSH_HOST],
      ...policy,
    });
    await engine.setConnectionConfig(handle, { ssh: { known_hosts: [KNOWN_HOST] } });
    return handle;
  }

  async function sshText(
    value: string,
    extra: Record<string, unknown>,
    code: ErrorCode,
    policy: InjectionPolicyInput = {},
  ): Promise<string> {
    const handle = await sshSecret(value, policy);
    return refusedText(
      handle,
      { type: "ssh", host: SSH_HOST, user: "deploy", command: "uptime", ...extra },
      code,
    );
  }

  it("a host led by a dash", async () => {
    expect(await sshText(WORD_START, { host: "-x" }, ErrorCode.INVALID_SSH_CONFIG)).toBe(
      "host and user must not start with '-'",
    );
  });

  it("a host that is no name", async () => {
    expect(await sshText(WORD_NAMES, { host: "a host" }, ErrorCode.INVALID_SSH_CONFIG)).toBe(
      "host and user must be names of letters, digits, '.', '_' and '-'",
    );
  });

  it("a host off the allowlist quotes it as sent", async () => {
    expect(await sshText(VALUE_HOST, { host: VALUE_HOST }, ErrorCode.HOST_NOT_ALLOWED)).toBe(
      `Host not in secret allowlist: ${VALUE_HOST}`,
    );
  });

  it("ssh is not on the command allowlist: the binary's name as words", async () => {
    const text = await sshText(WORD_ALLOWLIST, {}, ErrorCode.COMMAND_NOT_ALLOWED, {
      command_allowlist: [],
    });

    expect(text).toBe("Command not in secret allowlist: ssh");
  });

  it.runIf(process.platform === "win32")(
    "an MSYS ssh client: its directory is outside text, the words around it as they stand (win32 only)",
    async () => {
      const handle = await sshSecret(WORD_BINARY);
      await engine.setInjectionPolicy(handle, {
        command_allowlist: [installMsysClient("ssh")],
        host_allowlist: [SSH_HOST],
      });

      const text = await refusedText(
        handle,
        { type: "ssh", host: SSH_HOST, user: "deploy", command: "uptime" },
        ErrorCode.SSH_CLIENT_UNSUPPORTED,
      );

      expect(text).toBe(msysText());
    },
  );

  it("a host key that does not match quotes the host as sent", async () => {
    spawnMock.mockResolvedValue(spawned({ exit_code: 255, stderr: HOST_KEY_FAILURE }));

    const text = await sshText(VALUE_HOST, { host: VALUE_HOST }, ErrorCode.SSH_HOST_KEY_MISMATCH, {
      host_allowlist: [VALUE_HOST],
    });

    expect(text).toBe(`SSH host key does not match the pinned key for: ${VALUE_HOST}`);
  });
});

describe("the sftp context's sites", () => {
  async function sftpSecret(value: string, policy: InjectionPolicyInput = {}): Promise<string> {
    const sftp = installBinary("sftp");
    const handle = await storeSecret("sftp", value);
    await engine.setInjectionPolicy(handle, {
      command_allowlist: [sftp],
      host_allowlist: [SSH_HOST],
      local_dirs: [workDir],
      ...policy,
    });
    await engine.setConnectionConfig(handle, { ssh: { known_hosts: [KNOWN_HOST] } });
    return handle;
  }

  function sftpAction(extra: Record<string, unknown>): Record<string, unknown> {
    return {
      type: "sftp",
      host: SSH_HOST,
      user: "deploy",
      operation: "list",
      remote_path: "/srv",
      ...extra,
    };
  }

  async function sftpText(
    value: string,
    extra: Record<string, unknown>,
    code: ErrorCode,
    policy: InjectionPolicyInput = {},
  ): Promise<string> {
    const handle = await sftpSecret(value, policy);
    return refusedText(handle, sftpAction(extra), code);
  }

  const download = (localPath: string): Record<string, unknown> => ({
    operation: "download",
    remote_path: "/srv/report.csv",
    local_path: localPath,
  });

  const ROWS: [string, string, () => Record<string, unknown>, ErrorCode, string][] = [
    [
      "a host led by a dash",
      WORD_START,
      () => ({ host: "-x" }),
      ErrorCode.INVALID_SSH_CONFIG,
      "host and user must not start with '-'",
    ],
    [
      "a host that is no name",
      WORD_NAMES,
      () => ({ host: "a host" }),
      ErrorCode.INVALID_SSH_CONFIG,
      "host and user must be names of letters, digits, '.', '_' and '-'",
    ],
    [
      "a host off the allowlist quotes it as sent",
      VALUE_HOST,
      () => ({ host: VALUE_HOST }),
      ErrorCode.HOST_NOT_ALLOWED,
      `Host not in secret allowlist: ${VALUE_HOST}`,
    ],
    [
      "a download without a local path: the operation as a token",
      WORD_REQUIRED,
      () => ({ operation: "download", remote_path: "/srv/report.csv" }),
      ErrorCode.INVALID_INPUT,
      "local_path is required for download",
    ],
    [
      "a local path that is not absolute",
      WORD_ABSOLUTE,
      () => download("relative.csv"),
      ErrorCode.INVALID_INPUT,
      "sftp local path must be absolute",
    ],
    [
      "a local path that names a device",
      WORD_DEVICE,
      () => download(process.platform === "win32" ? "\\\\.\\pipe\\report" : "/dev/report"),
      ErrorCode.INVALID_INPUT,
      "sftp local path names a device",
    ],
    [
      "a local path with a glob character",
      WORD_GLOB,
      () => download(join(workDir, "report*.csv")),
      ErrorCode.INVALID_INPUT,
      "sftp local path must not contain glob characters",
    ],
    [
      "a local path with a .. segment",
      WORD_SEGMENT,
      () => download(`${workDir}${sep}a${sep}..${sep}report.csv`),
      ErrorCode.INVALID_INPUT,
      "sftp local path must not hold a .. segment",
    ],
    [
      "a local path with a .git segment",
      WORD_SEGMENT,
      () => download(`${workDir}${sep}.git${sep}report.csv`),
      ErrorCode.INVALID_INPUT,
      "sftp local path must not hold a .git segment",
    ],
    [
      "a download onto a path that ends in a separator",
      WORD_FILE,
      () => download(`${workDir}${sep}`),
      ErrorCode.INVALID_INPUT,
      "sftp download path must name a file",
    ],
    [
      "a remote path led by a dash",
      WORD_PARSED,
      () => ({ remote_path: "-x" }),
      ErrorCode.INVALID_INPUT,
      "sftp path must not start with '-' (would be parsed as an sftp option)",
    ],
    [
      "a remote path ending in a backslash",
      WORD_MERGE,
      () => ({ remote_path: "x\\" }),
      ErrorCode.INVALID_INPUT,
      "sftp path must not end with '\\' (would merge with the closing quote)",
    ],
    [
      "a remote path holding a double quote",
      WORD_CHARACTER,
      () => ({ remote_path: 'a"b' }),
      ErrorCode.INVALID_INPUT,
      "sftp path must not contain a double-quote character",
    ],
    [
      "a remote path holding a control character",
      WORD_NEWLINES,
      () => ({ remote_path: "a\u0001b" }),
      ErrorCode.INVALID_INPUT,
      "sftp path must not contain control characters or newlines",
    ],
    [
      "a transfer's remote path holding a backslash",
      WORD_BACKSLASH,
      () => ({ ...download(join(workDir, "report.csv")), remote_path: "a\\b" }),
      ErrorCode.INVALID_INPUT,
      "sftp remote path must not contain a backslash",
    ],
    [
      "paths too long for one batch command",
      WORD_BATCH,
      () => ({ remote_path: `/${"r".repeat(2100)}` }),
      ErrorCode.INVALID_INPUT,
      "sftp paths are too long for one batch command",
    ],
  ];

  it.each(ROWS)("%s", async (_title, value, extra, code, message) => {
    expect(await sftpText(value, extra(), code)).toBe(message);
  });

  it.runIf(process.platform === "win32")(
    "a local path on a network share (win32 only)",
    async () => {
      const text = await sftpText(
        WORD_SHARE,
        download("\\\\server\\share\\report.csv"),
        ErrorCode.INVALID_INPUT,
      );

      expect(text).toBe("sftp local path names a network share");
    },
  );

  it.runIf(process.platform === "win32")(
    "a local path with a name Windows reads differently (win32 only)",
    async () => {
      const text = await sftpText(
        WORD_WINDOWS,
        download(`${workDir}${sep}report.`),
        ErrorCode.INVALID_INPUT,
      );

      expect(text).toBe("sftp local path holds a name Windows reads differently");
    },
  );

  it("sftp is not on the command allowlist: the binary's name as words", async () => {
    const text = await sftpText(WORD_ALLOWLIST, {}, ErrorCode.COMMAND_NOT_ALLOWED, {
      command_allowlist: [],
    });

    expect(text).toBe("Command not in secret allowlist: sftp");
  });

  it.runIf(process.platform === "win32")(
    "an MSYS sftp client: its directory is outside text, the words around it as they stand (win32 only)",
    async () => {
      const handle = await sftpSecret(WORD_BINARY);
      await engine.setInjectionPolicy(handle, {
        command_allowlist: [installMsysClient("sftp")],
        host_allowlist: [SSH_HOST],
      });

      const text = await refusedText(handle, sftpAction({}), ErrorCode.SSH_CLIENT_UNSUPPORTED);

      expect(text).toBe(msysText());
    },
  );

  it.each<[string, Partial<SpawnCapturedResult>, ErrorCode, string]>([
    [
      "a host key that does not match quotes the host as sent",
      { exit_code: 255, stderr: HOST_KEY_FAILURE },
      ErrorCode.SSH_HOST_KEY_MISMATCH,
      `SSH host key does not match the pinned key for: ${VALUE_HOST}`,
    ],
    [
      "a client that does not spawn quotes the host as sent",
      { exit_code: null, spawn_failed: true },
      ErrorCode.SSH_CONNECT_FAILED,
      `SSH connection failed: ${VALUE_HOST}`,
    ],
    [
      "a connection that fails quotes the host as sent",
      { exit_code: 255 },
      ErrorCode.SSH_CONNECT_FAILED,
      `SSH connection failed: ${VALUE_HOST}`,
    ],
  ])("%s", async (_title, result, code, message) => {
    spawnMock.mockResolvedValue(spawned(result));

    const text = await sftpText(VALUE_HOST, { host: VALUE_HOST }, code, {
      host_allowlist: [VALUE_HOST],
    });

    expect(text).toBe(message);
  });
});

describe("the docker context's sites", () => {
  async function dockerText(
    value: string,
    image: unknown,
    code: ErrorCode,
    policy: InjectionPolicyInput = {},
  ): Promise<string> {
    const docker = installBinary("docker");
    const handle = await storeSecret("registry", value);
    await engine.setInjectionPolicy(handle, {
      host_allowlist: ["registry.example.com"],
      command_allowlist: [docker],
      ...policy,
    });
    return refusedText(handle, { type: "docker_registry", operation: "pull", image }, code);
  }

  it("an image led by a dash", async () => {
    expect(await dockerText(WORD_REFERENCE, "-x", ErrorCode.INVALID_INPUT)).toBe(
      "docker image reference must not start with '-'",
    );
  });

  it("docker names the image as sent", async () => {
    const image = `${VALUE_REGISTRY}.example:5000/team/app:1.0`;

    expect(await dockerText(VALUE_REGISTRY, image, ErrorCode.HOST_NOT_ALLOWED)).toBe(
      `Host not in secret allowlist: ${image}`,
    );
  });

  it("an image of Docker Hub: the default registry as words", async () => {
    expect(await dockerText(WORD_DOCKER, "library/nginx:1.0", ErrorCode.HOST_NOT_ALLOWED)).toBe(
      "Host not in secret allowlist: registry-1.docker.io",
    );
  });

  it("docker is not on the command allowlist: the binary's name as words", async () => {
    const text = await dockerText(
      WORD_ALLOWLIST,
      "registry.example.com/app:1.0",
      ErrorCode.COMMAND_NOT_ALLOWED,
      { command_allowlist: [] },
    );

    expect(text).toBe("Command not in secret allowlist: docker");
  });
});

const DB_USER = "dbadmin";
const VALUE_PRIVATE_HOST = "10.0.0.5";
const VALUE_ENGINE = "enginevalue";
const VALUE_GUESS = "guess";
const PAIR_ZZ = "zz";
const WORD_HEADER = "header";
const WORD_MUST = "must";
const WORD_QUERY = "query";
const WORD_LOOPBACK = "loopback";
const WORD_REDIRECTS = "redirects";
const WORD_TARGET = "target";
const WORD_ALLOWED = "allowed";
const WORD_RETURNED = "returned";
const WORD_STRING = "string";
const WORD_RANGE = "range";
const WORD_FORMED = "formed";
const WORD_SECRET = "secret";
const WORD_DOCUMENT = "document";
const WORD_ARRAY = "array";
const WORD_ENGINE = "engine";
const WORD_VALUES = "values";
const WORD_NAME = "name";
const WORD_INDEX = "index";
const WORD_POSITIVE = "positive";

function websocketAction(url: string, extra: Record<string, unknown> = {}): UseSecretAction {
  return { type: "websocket", url, injection: { type: "bearer" }, ...extra } as UseSecretAction;
}

/** The validator's answer for `url`, pinned to no address the connection-time lookup can serve, so the dial fails before a socket opens. */
function unservablePin(url: string): ValidatedUrl {
  return { url: new URL(url), resolvedAddresses: ["unservable"] };
}

async function databaseText(
  value: string,
  fields: Record<string, unknown>,
  code: ErrorCode,
  policy: InjectionPolicyInput = { host_allowlist: ["8.8.8.8"] },
): Promise<string> {
  const handle = await storeSecret("db", value);
  await engine.setInjectionPolicy(handle, policy);
  return refusedText(handle, { ...databaseAction(), ...fields }, code);
}

function installRedisAdapter(adapter: DbCommandAdapter): void {
  const internals = engine as unknown as {
    auditLogger: AuditLogger;
    databaseInjector: DatabaseInjector;
  };
  internals.databaseInjector = new DatabaseInjector(internals.auditLogger, {}, { redis: adapter });
}

describe("the http context's sites", () => {
  let server: Server;
  let port: number;
  let base: string;

  beforeAll(async () => {
    server = createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      if (url.pathname === "/loop") {
        res.writeHead(302, { Location: "/loop" });
        res.end();
      } else if (url.pathname === "/to") {
        res.writeHead(302, { Location: url.searchParams.get("location") ?? "/" });
        res.end();
      } else if (url.pathname === "/declared") {
        res.writeHead(200, { "Content-Length": String(MAX_HTTP_RESPONSE_BYTES + 1) });
        res.end();
      } else if (url.pathname === "/streamed") {
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.write(Buffer.alloc(MAX_HTTP_RESPONSE_BYTES + 1, 0x61));
        res.end();
      } else {
        res.writeHead(404);
        res.end();
      }
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    port = (server.address() as AddressInfo).port;
    base = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  async function httpText(
    value: string,
    url: string,
    code: ErrorCode,
    extra: Record<string, unknown> = {},
  ): Promise<string> {
    const handle = await storeSecret("http", value);
    await engine.setInjectionPolicy(handle, {
      url_allowlist: [`${base}/*`, `http://localhost:${port}/*`],
    });
    return refusedText(handle, httpAction(url, extra), code);
  }

  function redirectTo(location: string): string {
    return `${base}/to?location=${encodeURIComponent(location)}`;
  }

  it("a header injection without its name: the fixed words as they stand", async () => {
    const text = await httpText(WORD_HEADER, `${base}/x`, ErrorCode.INVALID_INJECTION_CONFIG, {
      injection: { type: "header" },
    });

    expect(text).toBe("header_name required for header injection");
  });

  it("a header injection named __proto__: the fixed words as they stand", async () => {
    const text = await httpText(WORD_MUST, `${base}/x`, ErrorCode.INVALID_INJECTION_CONFIG, {
      injection: { type: "header", header_name: "__proto__" },
    });

    expect(text).toBe("header_name must not be __proto__");
  });

  it("a query injection without its parameter: the fixed words as they stand", async () => {
    const text = await httpText(WORD_QUERY, `${base}/x`, ErrorCode.INVALID_INJECTION_CONFIG, {
      injection: { type: "query" },
    });

    expect(text).toBe("query_param required for query injection");
  });

  it("a chain past the redirect ceiling: the fixed words as they stand", async () => {
    const text = await httpText(
      WORD_REDIRECTS,
      `${base}/loop`,
      ErrorCode.REDIRECT_POLICY_VIOLATION,
    );

    expect(text).toBe("Too many redirects");
  });

  it("a redirect the validator refuses: its origin is outside text, redacted, the words around it as they stand", async () => {
    const text = await httpText(
      WORD_TARGET,
      redirectTo(`http://${WORD_TARGET}.invalid/`),
      ErrorCode.REDIRECT_POLICY_VIOLATION,
    );

    expect(text).toBe("Redirect target blocked: http://[REDACTED].invalid");
  });

  it("a redirect off the URL allowlist: its origin is outside text, redacted, the words around it as they stand", async () => {
    dnsLookupMock.mockResolvedValueOnce([{ address: "93.184.216.34", family: 4 }]);

    const text = await httpText(
      WORD_ALLOWLIST,
      redirectTo(`https://${WORD_ALLOWLIST}.invalid/`),
      ErrorCode.URL_NOT_ALLOWED,
    );

    expect(text).toBe("URL not in secret allowlist: https://[REDACTED].invalid");
  });

  it.each([
    ["a declared length", "declared"],
    ["a streamed body", "streamed"],
  ])("%s past the cap on the first hop quotes the URL as sent", async (_title, path) => {
    const url = `${base}/${path}?q=${WORD_EXCEEDS}`;

    const text = await httpText(WORD_EXCEEDS, url, ErrorCode.RESPONSE_TOO_LARGE);

    expect(text).toBe(
      `Response body from ${url} exceeds the ${MAX_HTTP_RESPONSE_BYTES}-byte limit`,
    );
  });

  it.each([
    ["a declared length", "declared"],
    ["a streamed body", "streamed"],
  ])(
    "%s past the cap after a redirect: the hop's origin is outside text, redacted, the words around it as they stand",
    async (_title, path) => {
      const text = await httpText(
        "o",
        redirectTo(`http://localhost:${port}/${path}`),
        ErrorCode.RESPONSE_TOO_LARGE,
      );

      expect(text).toBe(
        `Response body from http://l[REDACTED]calh[REDACTED]st:${port} exceeds the ${MAX_HTTP_RESPONSE_BYTES}-byte limit`,
      );
    },
  );
});

describe("the websocket context's sites", () => {
  async function websocketText(
    value: string,
    action: UseSecretAction,
    code: ErrorCode,
    policy: InjectionPolicyInput = {},
  ): Promise<string> {
    const handle = await storeSecret(`ws-${value}`, value);
    await engine.setInjectionPolicy(handle, policy);
    return refusedText(handle, action, code);
  }

  it("a response mode that loosens the policy's quotes the mode as sent and the policy's", async () => {
    const text = await websocketText(
      VALUE_MODE,
      websocketAction("wss://api.example.com/x", { response_mode: VALUE_MODE }),
      ErrorCode.RESPONSE_MODE_NOT_ALLOWED,
    );

    expect(text).toBe(
      `Response mode "${VALUE_MODE}" not allowed: secret policy is "filtered" and overrides may only tighten`,
    );
  });

  it("a URL off the allowlist quotes it as sent", async () => {
    const url = `wss://api.example.com/?q=${VALUE_URL}`;

    const text = await websocketText(VALUE_URL, websocketAction(url), ErrorCode.URL_NOT_ALLOWED);

    expect(text).toBe(`URL not in secret allowlist: ${url}`);
  });

  it("a host spelled in upper case reads like any other", async () => {
    const url = "wss://API.example.com/x";
    const texts: string[] = [];

    for (const value of ["e", PAIR_ZZ]) {
      validateUrlMock.mockResolvedValueOnce(unservablePin(url));
      texts.push(
        await websocketText(value, websocketAction(url), ErrorCode.WEBSOCKET_CONNECT_FAILED, {
          url_allowlist: ["wss://api.example.com/*"],
        }),
      );
    }

    expect(texts[0]).toBe(texts[1]);
    expect(texts[0]).toBe(`WebSocket connection failed: ${url}`);
  });
});

describe("the URL validator's sites", () => {
  it("http to a host that is no loopback: the scheme as a token, the words as they stand", async () => {
    const handle = await storeSecret("http", WORD_LOOPBACK);
    await engine.setInjectionPolicy(handle, { url_allowlist: ["http://api.example.com/*"] });

    const text = await refusedText(
      handle,
      httpAction("http://api.example.com/x"),
      ErrorCode.URL_HTTPS_REQUIRED,
    );

    expect(text).toBe("http: is only allowed for loopback addresses (localhost, 127.0.0.1, ::1)");
  });

  it("a scheme the context does not take: the secure scheme as a token, no scheme received", async () => {
    const handle = await storeSecret("ws", WORD_ALLOWED);
    await engine.setInjectionPolicy(handle, { url_allowlist: ["https://api.example.com/*"] });

    const text = await refusedText(
      handle,
      websocketAction("https://api.example.com/x"),
      ErrorCode.URL_HTTPS_REQUIRED,
    );

    expect(text).toBe("Only wss: URLs are allowed");
  });

  it("a private address literal quotes the URL as sent", async () => {
    const url = `https://10.0.0.1/${VALUE_URL}`;
    const handle = await storeSecret("http", VALUE_URL);
    await engine.setInjectionPolicy(handle, { url_allowlist: ["https://10.0.0.1/*"] });

    const text = await refusedText(handle, httpAction(url), ErrorCode.SSRF_BLOCKED);

    expect(text).toBe(`SSRF blocked: ${url} resolves to a private/internal IP address`);
  });

  it("a lookup that answers no address quotes the URL as sent", async () => {
    const url = `wss://api.example.com/${WORD_RETURNED}`;
    dnsLookupMock.mockResolvedValueOnce([]);
    const handle = await storeSecret("ws", WORD_RETURNED);
    await engine.setInjectionPolicy(handle, { url_allowlist: ["wss://api.example.com/*"] });

    const text = await refusedText(handle, websocketAction(url), ErrorCode.DNS_RESOLUTION_FAILED);

    expect(text).toBe(`DNS resolution failed for ${url}: no addresses returned`);
  });

  it("a DNS answer that holds the value is redacted there", async () => {
    dnsLookupMock.mockResolvedValueOnce([{ address: VALUE_ADDRESS, family: 4 }]);
    const handle = await storeSecret("http", VALUE_ADDRESS);
    await engine.setInjectionPolicy(handle, { url_allowlist: ["https://api.example.com/*"] });

    const text = await refusedText(
      handle,
      httpAction("https://api.example.com/x"),
      ErrorCode.SSRF_BLOCKED,
    );

    expectAbsent(text, VALUE_ADDRESS);
    expect(text).toBe("SSRF blocked: https://api.example.com/x resolves to private IP [REDACTED]");
  });

  it("a percent-encoded host answers no guess", async () => {
    const url = "wss://%67uess.example.com/";
    const texts: string[] = [];

    for (const value of [VALUE_GUESS, PAIR_ZZ]) {
      dnsLookupMock.mockRejectedValueOnce(lookupNotFound());
      const handle = await storeSecret(`ws-${value}`, value);
      await engine.setInjectionPolicy(handle, { url_allowlist: ["wss://*.example.com/*"] });
      texts.push(await refusedText(handle, websocketAction(url), ErrorCode.DNS_RESOLUTION_FAILED));
    }

    expect(texts[0]).toBe(texts[1]);
    expect(texts[0]).toBe(`DNS resolution failed for ${url}: ENOTFOUND`);
  });

  it("a host that is not well formed: the fixed words, no host", async () => {
    const text = await databaseText(
      WORD_FORMED,
      { host: `${WORD_FORMED}@db.example.com` },
      ErrorCode.SSRF_BLOCKED,
      { host_allowlist: ["*.example.com"] },
    );

    expect(text).toBe("SSRF blocked: the host is not a well-formed host");
  });

  it("a private address literal quotes the host as sent", async () => {
    const text = await databaseText(
      VALUE_PRIVATE_HOST,
      { host: VALUE_PRIVATE_HOST },
      ErrorCode.SSRF_BLOCKED,
      { host_allowlist: [VALUE_PRIVATE_HOST] },
    );

    expect(text).toBe(`SSRF blocked: ${VALUE_PRIVATE_HOST} is a private/internal IP address`);
  });

  it("a host the DNS answers with the value: the host as sent, the answer redacted there", async () => {
    const host = `${VALUE_ADDRESS}.example.com`;
    dnsLookupMock.mockResolvedValueOnce({ address: VALUE_ADDRESS, family: 4 });

    const text = await databaseText(VALUE_ADDRESS, { host }, ErrorCode.SSRF_BLOCKED, {
      host_allowlist: ["*.example.com"],
    });

    expect(text).toBe(`SSRF blocked: ${host} resolves to private IP [REDACTED]`);
  });

  it("a host the lookup fails for: the host as sent, the code as a token", async () => {
    const host = `${VALUE_HOST}.example.com`;
    dnsLookupMock.mockRejectedValueOnce(lookupNotFound());

    const text = await databaseText(VALUE_HOST, { host }, ErrorCode.DNS_RESOLUTION_FAILED, {
      host_allowlist: ["*.example.com"],
    });

    expect(text).toBe(`DNS resolution failed for ${host}: ENOTFOUND`);
  });
});

describe("the database context's sites", () => {
  it("an engine the context does not know quotes it as sent", async () => {
    const text = await databaseText(
      VALUE_ENGINE,
      { engine: VALUE_ENGINE },
      ErrorCode.UNSUPPORTED_DB_ENGINE,
    );

    expect(text).toBe(`Unsupported database engine: ${VALUE_ENGINE}`);
  });

  it("an engine that is no string: the fixed words as they stand", async () => {
    const text = await databaseText(WORD_STRING, { engine: 5 }, ErrorCode.UNSUPPORTED_DB_ENGINE);

    expect(text).toBe("Unsupported database engine: (not a string)");
  });

  it.each<[string, string, Record<string, unknown>]>([
    [
      "command must be a document for mongodb",
      WORD_DOCUMENT,
      { engine: "mongodb", command: "x", query: undefined },
    ],
    [
      "command must be a string array for redis",
      WORD_ARRAY,
      { engine: "redis", command: "x", database: "0", query: undefined },
    ],
    ["query is required for this engine", WORD_ENGINE, { query: "" }],
    ["params must be an array of at most 1000 values", WORD_VALUES, { params: "x" }],
    ["Invalid database name", WORD_NAME, { database: 5 }],
    [
      "database must be a non-negative integer index for redis",
      WORD_INDEX,
      { engine: "redis", command: ["PING"], database: "x", query: undefined },
    ],
    ["timeout_ms must be a positive integer up to 300000", WORD_POSITIVE, { timeout_ms: -1 }],
  ])(
    "an input the context refuses, %j: the fixed words as they stand",
    async (message, value, fields) => {
      expect(await databaseText(value, fields, ErrorCode.INVALID_DATABASE_CONFIG)).toBe(message);
    },
  );

  it("a host that is no string: the fixed words as they stand", async () => {
    const text = await databaseText(WORD_STRING, { host: 5 }, ErrorCode.INVALID_DATABASE_CONFIG);

    expect(text).toBe("host must be a string");
  });

  it("an embedded port out of range: the fixed words as they stand", async () => {
    const text = await databaseText(
      WORD_RANGE,
      { host: "db.example.com:70000" },
      ErrorCode.INVALID_DATABASE_CONFIG,
    );

    expect(text).toBe("embedded port out of range (1-65535)");
  });

  it.each<[string, Record<string, unknown>, string]>([
    [
      "a host off the allowlist quotes it as sent with the engine's port",
      { host: `${VALUE_HOST}.example.net` },
      `${VALUE_HOST}.example.net:5432`,
    ],
    [
      "a host that embeds its port is quoted as sent",
      { host: `${VALUE_HOST}.example.net:6543` },
      `${VALUE_HOST}.example.net:6543`,
    ],
    [
      "a host that embeds a port beside the action's port: both as sent",
      { host: `${VALUE_HOST}.example.net:6543`, port: 7000 },
      `${VALUE_HOST}.example.net:6543:7000`,
    ],
    [
      "a port sent as a string is quoted as sent",
      { host: `${VALUE_HOST}.example.net`, port: "7000" },
      `${VALUE_HOST}.example.net:7000`,
    ],
  ])("%s", async (_title, fields, target) => {
    const text = await databaseText(VALUE_HOST, fields, ErrorCode.HOST_NOT_ALLOWED);

    expect(text).toBe(`Host not in secret allowlist: ${target}`);
  });

  it("a secret that is not username:password: the fixed words as they stand", async () => {
    const text = await databaseText(WORD_SECRET, {}, ErrorCode.INVALID_DATABASE_CONFIG);

    expect(text).toBe("database secret must be in 'username:password' form");
  });

  it("the driver's sentence is redacted where it stands", async () => {
    installPostgresAdapter(
      new MockAdapter({
        connectError: new Error(`password authentication failed for user "${DB_USER}"`),
      }),
    );

    const text = await databaseText(`${DB_USER}:D`, {}, ErrorCode.DB_CONNECTION_FAILED);

    expectAbsent(text, DB_USER);
    expect(text).toBe(
      'Database connection failed: password authentication failed for user "[REDACTED]"',
    );
  });

  it("a query's driver error is outside text, redacted, the words around it as they stand", async () => {
    installPostgresAdapter(
      new MockAdapter({ queryError: new Error('syntax error at or near "D"') }),
    );

    const text = await databaseText(`${DB_USER}:D`, {}, ErrorCode.DB_QUERY_FAILED);

    expect(text).toBe('Database query failed: syntax error at or near "[REDACTED]"');
  });

  it("a command engine's driver error is outside text, redacted, the words around it as they stand", async () => {
    installRedisAdapter(new MockCommandAdapter({ error: new Error("ERR unknown command 'D'") }));

    const text = await databaseText(
      `${DB_USER}:D`,
      { engine: "redis", command: ["D"], database: "0", query: undefined },
      ErrorCode.DB_QUERY_FAILED,
    );

    expect(text).toBe("Database query failed: ERR unknown command '[REDACTED]'");
  });
});

const MAIL_HOST = "fixture.example.com";
const VALUE_MAIL = "fixture";
const MAIL_SECRET = `u:${VALUE_MAIL}`;
const REPLY_SECRET = `u:${PW_FIXTURE}`;
const MAIL_KEY = readFileSync(new URL("./__fixtures__/certs/rsa-key.pem", import.meta.url), "utf8");
const MAIL_CERT = readFileSync(
  new URL("./__fixtures__/certs/rsa-cert.pem", import.meta.url),
  "utf8",
);
const TRUSTED_MAIL: MailConnectionConfig = { tls: { ca: MAIL_CERT } };
const PLAINTEXT_MAIL: MailConnectionConfig = { tls: false };
const VALUE_RECIPIENT = "rcptvalue@example.com";
const VALUE_DATE = "datevalue";
const VALUE_UID = "42";
const VALUE_FLAG = "flagvalue";
const VALUE_PARTS = "partsvalue";
const WORD_EXPLICIT = "explicit";
const WORD_MANY = "many";
const WORD_REGULAR = "regular";
const WORD_MESSAGE = "message";
const WORD_STORE = "store";
const SMTP_GREETING = "220 fake ESMTP\r\n";
const IMAP_GREETING = "* OK ready\r\n";

const mailServers: NetServer[] = [];
const mailSockets = new Set<Socket>();

/** A mail server on loopback: `greeting` once a client connects (once the handshake ends, where `tls`), then `answer`'s text for each line it reads. */
async function mailServer(
  tls: boolean,
  greeting: string,
  answer: (line: string) => string = () => "",
): Promise<number> {
  const server = createNetServer((raw) => {
    mailSockets.add(raw);
    raw.on("close", () => mailSockets.delete(raw));
    raw.on("error", () => undefined);
    const stream = tls
      ? new TLSSocket(raw, {
          isServer: true,
          secureContext: createSecureContext({ key: MAIL_KEY, cert: MAIL_CERT }),
        })
      : raw;
    stream.on("error", () => undefined);
    let pending = "";
    stream.on("data", (chunk: Buffer) => {
      pending += chunk.toString("latin1");
      for (let end = pending.indexOf("\r\n"); end !== -1; end = pending.indexOf("\r\n")) {
        const reply = answer(pending.slice(0, end));
        pending = pending.slice(end + 2);
        if (reply !== "") stream.write(reply);
      }
    });
    const greet = (): void => {
      if (greeting !== "") stream.write(greeting);
    };
    if (tls) stream.once("secure", greet);
    else greet();
  });
  mailServers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return (server.address() as AddressInfo).port;
}

async function closeMailServers(): Promise<void> {
  for (const socket of mailSockets) socket.destroy();
  await Promise.all(
    mailServers
      .splice(0)
      .map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
  );
}

/** A loopback port nothing listens on. */
async function closedPort(): Promise<number> {
  const server = createNetServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

/** The validator's answer for the mail host, pinned to the loopback server on `port`. */
function pinMailHost(port: number): void {
  validateHostPortMock.mockResolvedValueOnce({
    host: MAIL_HOST,
    port,
    resolvedAddress: "127.0.0.1",
  });
}

/** A secret holding `value`, its policy admitting the mail host, its mail connection config `mail`. */
async function mailSecret(
  value: string,
  mail?: MailConnectionConfig,
  policy: InjectionPolicyInput = {},
): Promise<string> {
  const handle = await storeSecret("mail", value);
  await engine.setInjectionPolicy(handle, { host_allowlist: [MAIL_HOST], ...policy });
  if (mail !== undefined) await engine.setConnectionConfig(handle, { mail });
  return handle;
}

/** An OAuth secret whose access token is `token`, its policy and mail config as `mailSecret`'s. */
async function oauthMailSecret(token: string, mail: MailConnectionConfig): Promise<string> {
  const { handle, secretId } = await engine.createOAuthSecret("mailbox", {
    provider: "google",
    grant_type: "client_credentials",
    token_endpoint: "https://oauth.example.com/token",
    client_id: "cid",
  });
  await engine.completeOAuthFlow(secretId, token);
  await engine.setInjectionPolicy(handle, { host_allowlist: [MAIL_HOST] });
  await engine.setConnectionConfig(handle, { mail });
  return handle;
}

describe("the smtp context's sites", () => {
  afterEach(closeMailServers);

  const ATTACHING: InjectionPolicyInput = { smtp_recipient_allowlist: ["dev@example.com"] };

  function smtpAction(extra: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      type: "smtp",
      host: MAIL_HOST,
      security: "tls",
      from: "ops@example.com",
      to: ["dev@example.com"],
      subject: "s",
      text: "t",
      timeout_ms: 5_000,
      ...extra,
    };
  }

  async function smtpText(
    value: string,
    extra: Record<string, unknown>,
    code: ErrorCode,
    policy: InjectionPolicyInput = {},
  ): Promise<string> {
    const handle = await mailSecret(value, undefined, policy);
    return refusedText(handle, smtpAction(extra), code);
  }

  /** An SMTP server's answer to a line: `250` to EHLO with AUTH PLAIN on offer, `235` to AUTH, `354` to DATA, `250` to the rest — each verb in `over` answered as it says. */
  function smtpAnswer(over: Record<string, string> = {}): (line: string) => string {
    let inData = false;
    return (line) => {
      if (inData) {
        if (line !== ".") return "";
        inData = false;
        return "250 queued\r\n";
      }
      const verb = (line.split(" ")[0] ?? "").toUpperCase();
      const own = over[verb];
      if (own !== undefined) return own;
      if (verb === "EHLO") return "250-fake\r\n250 AUTH PLAIN\r\n";
      if (verb === "AUTH") return "235 accepted\r\n";
      if (verb === "DATA") {
        inData = true;
        return "354 go on\r\n";
      }
      if (verb === "QUIT") return "221 bye\r\n";
      return "250 ok\r\n";
    };
  }

  /** The refusal of a send whose mail host is pinned to the server on `port`. */
  async function deliveryText(
    handle: string,
    port: number,
    extra: Record<string, unknown>,
    code: ErrorCode = ErrorCode.SMTP_DELIVERY_FAILED,
  ): Promise<string> {
    pinMailHost(port);
    return refusedText(handle, smtpAction(extra), code);
  }

  function installSmtpStat(stat: NonNullable<SmtpInjectorDeps["stat"]>): void {
    (engine as unknown as { smtpInjector: SmtpInjector }).smtpInjector = new SmtpInjector({ stat });
  }

  /** `count` attachments in the work directory, each a file of one byte. */
  function attachments(count: number): { path: string }[] {
    return Array.from({ length: count }, (_v, i) => {
      const path = join(workDir, `a${i}.bin`);
      writeFileSync(path, "x");
      return { path };
    });
  }

  it("a host that is no string: the fixed words as they stand", async () => {
    const text = await smtpText(WORD_STRING, { host: 5 }, ErrorCode.INVALID_INPUT);

    expect(text).toBe("host must be a string");
  });

  it("an embedded port out of range: the fixed words as they stand", async () => {
    const text = await smtpText(
      WORD_RANGE,
      { host: `${MAIL_HOST}:70000` },
      ErrorCode.INVALID_INPUT,
    );

    expect(text).toBe("embedded port out of range (1-65535)");
  });

  it.each<[string, Record<string, unknown>, string]>([
    [
      "a host off the allowlist quotes it as sent with the default port",
      { host: `${VALUE_HOST}.example.net` },
      `${VALUE_HOST}.example.net:465`,
    ],
    [
      "a host that embeds its port is quoted as sent",
      { host: `${VALUE_HOST}.example.net:2525` },
      `${VALUE_HOST}.example.net:2525`,
    ],
    [
      "a host that embeds a port beside the action's port: both as sent",
      { host: `${VALUE_HOST}.example.net:2525`, port: 7000 },
      `${VALUE_HOST}.example.net:2525:7000`,
    ],
    [
      "a port sent as a string is quoted as sent",
      { host: `${VALUE_HOST}.example.net`, port: "7000" },
      `${VALUE_HOST}.example.net:7000`,
    ],
  ])("%s", async (_title, fields, target) => {
    const text = await smtpText(VALUE_HOST, fields, ErrorCode.HOST_NOT_ALLOWED);

    expect(text).toBe(`Host not in secret allowlist: ${target}`);
  });

  it.each<[string, Record<string, unknown>]>([
    ["to[1]", { to: ["dev@example.com", VALUE_RECIPIENT] }],
    ["cc[1]", { cc: ["dev@example.com", VALUE_RECIPIENT] }],
    ["bcc[0]", { bcc: [VALUE_RECIPIENT] }],
  ])("a recipient that is the value is named as sent (%s)", async (_path, fields) => {
    const text = await smtpText(
      VALUE_RECIPIENT,
      fields,
      ErrorCode.RECIPIENT_NOT_ALLOWED,
      ATTACHING,
    );

    expect(text).toBe(`Recipient not in secret allowlist: ${VALUE_RECIPIENT}`);
  });

  it("attachments without a recipient allowlist: the fixed words as they stand", async () => {
    const text = await smtpText(
      WORD_EXPLICIT,
      { attachments: attachments(1) },
      ErrorCode.ATTACHMENT_POLICY_REQUIRED,
    );

    expect(text).toBe(
      "Attachments require an explicit recipient allowlist before they can be sent: configure one via secret allow <handle> --recipient",
    );
  });

  it("more attachments than the cap: the cap as a number, the words as they stand", async () => {
    const many = Array.from({ length: MAX_SMTP_ATTACHMENTS + 1 }, (_v, i) => ({
      path: join(workDir, `f${i}`),
    }));

    const text = await smtpText(
      WORD_MANY,
      { attachments: many },
      ErrorCode.ATTACHMENT_REJECTED,
      ATTACHING,
    );

    expect(text).toBe(`Attachment rejected: too many attachments (max ${MAX_SMTP_ATTACHMENTS})`);
  });

  it.each<[string, string, () => string, string]>([
    [
      "a path outside the listed directories",
      WORD_DIRECTORY,
      () => join(workDir, "report.csv"),
      "an attachment path is not inside a directory the secret's policy lists",
    ],
    [
      "a path that names a device",
      WORD_DEVICE,
      () => (process.platform === "win32" ? "\\\\.\\NUL" : "/dev/null"),
      "an attachment path names a device",
    ],
  ])("%s: the fixed words as they stand", async (_title, value, path, reason) => {
    const text = await smtpText(
      value,
      { attachments: [{ path: path() }] },
      ErrorCode.ATTACHMENT_REJECTED,
      ATTACHING,
    );

    expect(text).toBe(`Attachment rejected: ${reason}`);
  });

  it.runIf(process.platform === "win32")(
    "a path on a network share: the fixed words as they stand (win32 only)",
    async () => {
      const text = await smtpText(
        WORD_SHARE,
        { attachments: [{ path: "//server/share/f" }] },
        ErrorCode.ATTACHMENT_REJECTED,
        ATTACHING,
      );

      expect(text).toBe("Attachment rejected: an attachment path names a network share");
    },
  );

  it.each<[string, string, number, { size: number; isFile(): boolean }, string]>([
    [
      "an attachment that is no regular file",
      WORD_REGULAR,
      1,
      { size: 1, isFile: () => false },
      "an attachment path is not a regular file",
    ],
    [
      "an attachment past the per-file cap",
      WORD_EXCEEDS,
      1,
      { size: MAX_ATTACHMENT_BYTES + 1, isFile: () => true },
      `an attachment exceeds the ${MAX_ATTACHMENT_BYTES}-byte per-file limit`,
    ],
    [
      "attachments past the per-message cap",
      WORD_MESSAGE,
      Math.floor(MAX_ATTACHMENT_TOTAL_BYTES / MAX_ATTACHMENT_BYTES) + 1,
      { size: MAX_ATTACHMENT_BYTES, isFile: () => true },
      `attachments exceed the ${MAX_ATTACHMENT_TOTAL_BYTES}-byte per-message limit`,
    ],
  ])(
    "%s: the caps as numbers, the words as they stand",
    async (_title, value, count, stat, reason) => {
      installSmtpStat(() => Promise.resolve(stat));

      const text = await smtpText(
        value,
        { attachments: attachments(count) },
        ErrorCode.ATTACHMENT_REJECTED,
        { ...ATTACHING, local_dirs: [workDir] },
      );

      expect(text).toBe(`Attachment rejected: ${reason}`);
    },
  );

  it("a reserved header: the fixed words as they stand", async () => {
    const text = await smtpText(
      WORD_HEADER,
      { headers: { Bcc: "hidden@example.com" } },
      ErrorCode.INVALID_INPUT,
    );

    expect(text).toBe("message assembly failed: a reserved or malformed header field was supplied");
  });

  it("a host that is not well formed: the fixed words, no host", async () => {
    const text = await smtpText(
      WORD_FORMED,
      { host: `${WORD_FORMED}@mail.example.com` },
      ErrorCode.SSRF_BLOCKED,
      { host_allowlist: ["*.example.com"] },
    );

    expect(text).toBe("SSRF blocked: the host is not a well-formed host");
  });

  it("a private address literal quotes the host as sent", async () => {
    const text = await smtpText(
      VALUE_PRIVATE_HOST,
      { host: VALUE_PRIVATE_HOST },
      ErrorCode.SSRF_BLOCKED,
      { host_allowlist: [VALUE_PRIVATE_HOST] },
    );

    expect(text).toBe(`SSRF blocked: ${VALUE_PRIVATE_HOST} is a private/internal IP address`);
  });

  it("a host the DNS answers with the value: the host as sent, the answer redacted there", async () => {
    const host = `${VALUE_ADDRESS}.example.com`;
    dnsLookupMock.mockResolvedValueOnce({ address: VALUE_ADDRESS, family: 4 });

    const text = await smtpText(VALUE_ADDRESS, { host }, ErrorCode.SSRF_BLOCKED, {
      host_allowlist: ["*.example.com"],
    });

    expect(text).toBe(`SSRF blocked: ${host} resolves to private IP [REDACTED]`);
  });

  it("a host the lookup fails for: the host as sent, the code as a token", async () => {
    const host = `${VALUE_HOST}.example.com`;
    dnsLookupMock.mockRejectedValueOnce(lookupNotFound());

    const text = await smtpText(VALUE_HOST, { host }, ErrorCode.DNS_RESOLUTION_FAILED, {
      host_allowlist: ["*.example.com"],
    });

    expect(text).toBe(`DNS resolution failed for ${host}: ENOTFOUND`);
  });

  it("a secret that is not username:password: the fixed words as they stand", async () => {
    const text = await smtpText(WORD_SECRET, { host: "127.0.0.1" }, ErrorCode.INVALID_INPUT, {
      host_allowlist: ["127.0.0.1"],
    });

    expect(text).toBe("SMTP secret must be in 'username:password' form");
  });

  it.each<[string, (port: number) => Record<string, unknown>]>([
    ["beside it", (port) => ({ port })],
    ["embedded in the host", (port) => ({ host: `${MAIL_HOST}:${port}` })],
  ])(
    "the origin of a failed delivery is the host as sent with its port (%s)",
    async (_title, fields) => {
      const port = await mailServer(
        false,
        SMTP_GREETING,
        smtpAnswer({ RCPT: "550 no such user\r\n" }),
      );
      const handle = await mailSecret(MAIL_SECRET, PLAINTEXT_MAIL);

      const text = await deliveryText(handle, port, fields(port));

      expect(text).toBe(`SMTP delivery failed: ${MAIL_HOST}:${port}`);
    },
  );

  it.each<[string, string, Record<string, string>]>([
    ["a greeting that is no reply line (the channel's failure)", "garbage\r\n", {}],
    ["a greeting with another code", "554 not now\r\n", {}],
    ["an EHLO the server refuses", SMTP_GREETING, { EHLO: "502 not here\r\n" }],
    [
      "a password with neither PLAIN nor LOGIN on offer",
      SMTP_GREETING,
      { EHLO: "250 AUTH CRAM-MD5\r\n" },
    ],
  ])("%s: the origin is the host as sent with its port", async (_title, greeting, over) => {
    const port = await mailServer(false, greeting, smtpAnswer(over));
    const handle = await mailSecret(MAIL_SECRET, PLAINTEXT_MAIL);

    const text = await deliveryText(handle, port, { port });

    expect(text).toBe(`SMTP delivery failed: ${MAIL_HOST}:${port}`);
  });

  it("a server nothing listens on: the origin is the host as sent with its port", async () => {
    const port = await closedPort();
    const handle = await mailSecret(MAIL_SECRET, PLAINTEXT_MAIL);

    const text = await deliveryText(handle, port, { port });

    expect(text).toBe(`SMTP delivery failed: ${MAIL_HOST}:${port}`);
  });

  it("a TLS handshake that never ends: the origin is the host as sent with its port", async () => {
    const port = await mailServer(false, "");
    const handle = await mailSecret(MAIL_SECRET);

    const text = await deliveryText(handle, port, { port, timeout_ms: 1 });

    expect(text).toBe(`SMTP delivery failed: ${MAIL_HOST}:${port}`);
  });

  it("a security that is neither tls nor starttls: the origin is the host as sent with its port", async () => {
    const port = await mailServer(false, SMTP_GREETING, smtpAnswer());
    const handle = await mailSecret(MAIL_SECRET);

    const text = await deliveryText(handle, port, { port, security: "plain" });

    expect(text).toBe(`SMTP delivery failed: ${MAIL_HOST}:${port}`);
  });

  it.each<[string, Record<string, string>]>([
    ["XOAUTH2 not on offer", {}],
    ["an XOAUTH2 login the server refuses", { EHLO: "250 AUTH XOAUTH2\r\n", AUTH: "535 no\r\n" }],
  ])("%s: the origin is the host as sent with its port", async (_title, over) => {
    const port = await mailServer(false, SMTP_GREETING, smtpAnswer(over));
    const handle = await oauthMailSecret(VALUE_MAIL, PLAINTEXT_MAIL);

    const text = await deliveryText(handle, port, { port });

    expect(text).toBe(`SMTP delivery failed: ${MAIL_HOST}:${port}`);
  });

  it.each<[string, (port: number) => Record<string, unknown>, (port: number) => string]>([
    ["the host as sent", (port) => ({ port }), () => MAIL_HOST],
    [
      "a host that embeds its port, as sent",
      (port) => ({ host: `${MAIL_HOST}:${port}` }),
      (port) => `${MAIL_HOST}:${port}`,
    ],
  ])("a server without STARTTLS: %s", async (_title, fields, named) => {
    const port = await mailServer(false, SMTP_GREETING, smtpAnswer());
    const handle = await mailSecret(MAIL_SECRET);

    const text = await deliveryText(
      handle,
      port,
      { ...fields(port), security: "starttls" },
      ErrorCode.SMTP_STARTTLS_UNAVAILABLE,
    );

    expect(text).toBe(`SMTP STARTTLS is required but not available on ${named(port)}`);
  });

  it("a server's reply that holds the password is not in the message", async () => {
    const port = await mailServer(
      false,
      SMTP_GREETING,
      smtpAnswer({ AUTH: `535 5.7.8 ${PW_FIXTURE} rejected\r\n` }),
    );
    const handle = await mailSecret(REPLY_SECRET, PLAINTEXT_MAIL);

    const text = await deliveryText(handle, port, { port });

    expectAbsent(text, PW_FIXTURE);
    expect(text).toBe(`SMTP delivery failed: ${MAIL_HOST}:${port}`);
  });
});

describe("the imap context's sites", () => {
  afterEach(closeMailServers);

  const SEARCH = { kind: "search", unseen: true };
  const FETCH = { kind: "fetch", uids: [1], parts: "envelope" };
  const STORE = { kind: "store", uids: [1], add_flags: ["\\Seen"] };
  const MOVE = { kind: "move", uids: [1], target_mailbox: "Archive" };
  const COPY = { kind: "copy", uids: [1], target_mailbox: "Archive" };
  const EXPUNGE = { kind: "expunge" };

  function imapAction(
    operation: Record<string, unknown>,
    extra: Record<string, unknown> = {},
  ): Record<string, unknown> {
    return {
      type: "imap",
      host: MAIL_HOST,
      mailbox: "INBOX",
      operation,
      timeout_ms: 5_000,
      ...extra,
    };
  }

  async function imapText(
    value: string,
    extra: Record<string, unknown>,
    code: ErrorCode,
    policy: InjectionPolicyInput = {},
    operation: Record<string, unknown> = SEARCH,
  ): Promise<string> {
    const handle = await mailSecret(value, undefined, policy);
    return refusedText(handle, imapAction(operation, extra), code);
  }

  /** An IMAP server's answer to a command line: a tagged OK, with `* CAPABILITY <capabilities>` before it for CAPABILITY — each command named in `over` answered as it says. */
  function imapAnswer(
    over: Record<string, (tag: string) => string> = {},
    capabilities = "IMAP4rev1 MOVE",
  ): (line: string) => string {
    return (line) => {
      const [tag = "", first = "", second = ""] = line.split(" ");
      const verb = first.toUpperCase();
      const name = verb === "UID" ? `UID ${second.toUpperCase()}` : verb;
      const own = over[name];
      if (own !== undefined) return own(tag);
      if (name === "CAPABILITY") return `* CAPABILITY ${capabilities}\r\n${tag} OK done\r\n`;
      if (name === "LOGOUT") return `* BYE bye\r\n${tag} OK done\r\n`;
      return `${tag} OK done\r\n`;
    };
  }

  const refuse = (tag: string): string => `${tag} NO refused\r\n`;

  /** The refusal of an operation whose mail host is pinned to the server on `port`. */
  async function operationText(
    handle: string,
    port: number,
    operation: Record<string, unknown>,
    code: ErrorCode = ErrorCode.IMAP_OPERATION_FAILED,
    extra: Record<string, unknown> = {},
  ): Promise<string> {
    pinMailHost(port);
    return refusedText(handle, imapAction(operation, { port, ...extra }), code);
  }

  it("a host that is no string: the fixed words as they stand", async () => {
    const text = await imapText(WORD_STRING, { host: 5 }, ErrorCode.INVALID_INPUT);

    expect(text).toBe("host must be a string");
  });

  it("an embedded port out of range: the fixed words as they stand", async () => {
    const text = await imapText(
      WORD_RANGE,
      { host: `${MAIL_HOST}:70000` },
      ErrorCode.INVALID_INPUT,
    );

    expect(text).toBe("embedded port out of range (1-65535)");
  });

  it("a mutation under a read-only policy: the operation as a token", async () => {
    const text = await imapText(
      WORD_STORE,
      {},
      ErrorCode.IMAP_MUTATION_NOT_ALLOWED,
      { imap_read_only: true },
      STORE,
    );

    expect(text).toBe(
      "IMAP mutation 'store' is not allowed: this secret's IMAP policy is read-only",
    );
  });

  it.each<[string, Record<string, unknown>, string]>([
    [
      "a host off the allowlist quotes it as sent with the default port",
      { host: `${VALUE_HOST}.example.net` },
      `${VALUE_HOST}.example.net:993`,
    ],
    [
      "a host that embeds its port is quoted as sent",
      { host: `${VALUE_HOST}.example.net:1993` },
      `${VALUE_HOST}.example.net:1993`,
    ],
    [
      "a host that embeds a port beside the action's port: both as sent",
      { host: `${VALUE_HOST}.example.net:1993`, port: 7000 },
      `${VALUE_HOST}.example.net:1993:7000`,
    ],
    [
      "a port sent as a string is quoted as sent",
      { host: `${VALUE_HOST}.example.net`, port: "7000" },
      `${VALUE_HOST}.example.net:7000`,
    ],
  ])("%s", async (_title, fields, target) => {
    const text = await imapText(VALUE_HOST, fields, ErrorCode.HOST_NOT_ALLOWED);

    expect(text).toBe(`Host not in secret allowlist: ${target}`);
  });

  it("a host that is not well formed: the fixed words, no host", async () => {
    const text = await imapText(
      WORD_FORMED,
      { host: `${WORD_FORMED}@mail.example.com` },
      ErrorCode.SSRF_BLOCKED,
      { host_allowlist: ["*.example.com"] },
    );

    expect(text).toBe("SSRF blocked: the host is not a well-formed host");
  });

  it("a private address literal quotes the host as sent", async () => {
    const text = await imapText(
      VALUE_PRIVATE_HOST,
      { host: VALUE_PRIVATE_HOST },
      ErrorCode.SSRF_BLOCKED,
      { host_allowlist: [VALUE_PRIVATE_HOST] },
    );

    expect(text).toBe(`SSRF blocked: ${VALUE_PRIVATE_HOST} is a private/internal IP address`);
  });

  it("a host the DNS answers with the value: the host as sent, the answer redacted there", async () => {
    const host = `${VALUE_ADDRESS}.example.com`;
    dnsLookupMock.mockResolvedValueOnce({ address: VALUE_ADDRESS, family: 4 });

    const text = await imapText(VALUE_ADDRESS, { host }, ErrorCode.SSRF_BLOCKED, {
      host_allowlist: ["*.example.com"],
    });

    expect(text).toBe(`SSRF blocked: ${host} resolves to private IP [REDACTED]`);
  });

  it("a host the lookup fails for: the host as sent, the code as a token", async () => {
    const host = `${VALUE_HOST}.example.com`;
    dnsLookupMock.mockRejectedValueOnce(lookupNotFound());

    const text = await imapText(VALUE_HOST, { host }, ErrorCode.DNS_RESOLUTION_FAILED, {
      host_allowlist: ["*.example.com"],
    });

    expect(text).toBe(`DNS resolution failed for ${host}: ENOTFOUND`);
  });

  it("a secret that is not username:password: the fixed words as they stand", async () => {
    const text = await imapText(WORD_SECRET, { host: "127.0.0.1" }, ErrorCode.INVALID_INPUT, {
      host_allowlist: ["127.0.0.1"],
    });

    expect(text).toBe("IMAP secret must be in 'username:password' form");
  });

  it.each<[string, string, string]>([
    ["a line holding a NUL byte (the channel's failure)", "* OK \u0000\r\n", "read"],
    ["a literal past the cap, at its announcement", "* OK {2000000}\r\n", "read"],
    ["a greeting that is no OK", "* BYE go away\r\n", "connect"],
  ])("%s: the origin is the host as sent with its port", async (_title, greeting, verb) => {
    const port = await mailServer(true, greeting, imapAnswer());
    const handle = await mailSecret(MAIL_SECRET, TRUSTED_MAIL);

    const text = await operationText(handle, port, SEARCH);

    expect(text).toBe(`IMAP operation '${verb}' failed: ${MAIL_HOST}:${port}`);
  });

  it("a certificate the client cannot verify: the origin is the host as sent with its port", async () => {
    const port = await mailServer(true, IMAP_GREETING, imapAnswer());
    const handle = await mailSecret(MAIL_SECRET);

    const text = await operationText(handle, port, SEARCH);

    expect(text).toBe(`IMAP operation 'connect' failed: ${MAIL_HOST}:${port}`);
  });

  it("a TLS handshake that never ends: the origin is the host as sent with its port", async () => {
    const port = await mailServer(false, "");
    const handle = await mailSecret(MAIL_SECRET, TRUSTED_MAIL);

    const text = await operationText(handle, port, SEARCH, ErrorCode.IMAP_OPERATION_FAILED, {
      timeout_ms: 1,
    });

    expect(text).toBe(`IMAP operation 'connect' failed: ${MAIL_HOST}:${port}`);
  });

  it.each<[string, (line: string) => string, Record<string, unknown>, string]>([
    ["a CAPABILITY the server refuses", imapAnswer({ CAPABILITY: refuse }), SEARCH, "capability"],
    ["a LOGIN the server refuses", imapAnswer({ LOGIN: refuse }), SEARCH, "login"],
    [
      "an EXAMINE the server refuses: the verb as a token",
      imapAnswer({ EXAMINE: refuse }),
      SEARCH,
      "examine",
    ],
    [
      "a SELECT the server refuses: the verb as a token",
      imapAnswer({ SELECT: refuse }),
      STORE,
      "select",
    ],
    ["a search the server refuses", imapAnswer({ "UID SEARCH": refuse }), SEARCH, "search"],
    ["a fetch the server refuses", imapAnswer({ "UID FETCH": refuse }), FETCH, "fetch"],
    [
      "a fetch answer nested past the parser's depth",
      imapAnswer({
        "UID FETCH": (tag) => `* 1 FETCH ${"(".repeat(40)}${")".repeat(40)}\r\n${tag} OK done\r\n`,
      }),
      FETCH,
      "fetch",
    ],
    ["a move the server refuses", imapAnswer({ "UID MOVE": refuse }), MOVE, "move"],
    [
      "a move's copy the server refuses",
      imapAnswer({ "UID COPY": refuse }, "IMAP4rev1 UIDPLUS"),
      MOVE,
      "move",
    ],
    [
      "a move's expunge the server refuses",
      imapAnswer({ "UID EXPUNGE": refuse }, "IMAP4rev1 UIDPLUS"),
      MOVE,
      "expunge",
    ],
    ["a copy the server refuses", imapAnswer({ "UID COPY": refuse }), COPY, "copy"],
    ["an expunge the server refuses", imapAnswer({ EXPUNGE: refuse }), EXPUNGE, "expunge"],
    ["a store the server refuses", imapAnswer({ "UID STORE": refuse }), STORE, "store"],
    ["a stray continuation", imapAnswer({ "UID SEARCH": () => "+ more\r\n" }), SEARCH, "read"],
    [
      "a tagged line that is no status",
      imapAnswer({ "UID SEARCH": (tag) => `${tag} HUH\r\n` }),
      SEARCH,
      "read",
    ],
    [
      "a tagged line of another tag",
      imapAnswer({ "UID SEARCH": () => "Z9 OK done\r\n" }),
      SEARCH,
      "read",
    ],
  ])(
    "%s: the origin is the host as sent with its port",
    async (_title, answer, operation, verb) => {
      const port = await mailServer(true, IMAP_GREETING, answer);
      const handle = await mailSecret(MAIL_SECRET, TRUSTED_MAIL);

      const text = await operationText(handle, port, operation);

      expect(text).toBe(`IMAP operation '${verb}' failed: ${MAIL_HOST}:${port}`);
    },
  );

  it("a literal the server does not continue: the origin is the host as sent with its port", async () => {
    const port = await mailServer(true, IMAP_GREETING, imapAnswer({ EXAMINE: refuse }));
    const handle = await mailSecret(MAIL_SECRET, TRUSTED_MAIL);

    const text = await operationText(handle, port, SEARCH, ErrorCode.IMAP_OPERATION_FAILED, {
      mailbox: 'IN"BOX',
    });

    expect(text).toBe(`IMAP operation 'literal' failed: ${MAIL_HOST}:${port}`);
  });

  it("a server with neither MOVE nor UIDPLUS: the origin is the host as sent with its port", async () => {
    const port = await mailServer(true, IMAP_GREETING, imapAnswer({}, "IMAP4rev1"));
    const handle = await mailSecret(MAIL_SECRET, TRUSTED_MAIL);

    const text = await operationText(handle, port, MOVE);

    expect(text).toBe(
      `IMAP operation 'move' refused: ${MAIL_HOST}:${port} advertises neither MOVE (RFC 6851) nor UIDPLUS (RFC 4315), so a move could only complete with a mailbox-wide EXPUNGE; use 'copy', then 'store' (\\Deleted) and 'expunge' explicitly if that is acceptable`,
    );
  });

  it("an XOAUTH2 login the server refuses: the origin is the host as sent with its port", async () => {
    let sasl: string | undefined;
    const answer = imapAnswer({
      AUTHENTICATE: (tag) => {
        sasl = tag;
        return "+ \r\n";
      },
    });
    const port = await mailServer(true, IMAP_GREETING, (line) => {
      if (sasl === undefined) return answer(line);
      const tag = sasl;
      sasl = undefined;
      return refuse(tag);
    });
    const handle = await oauthMailSecret(VALUE_MAIL, TRUSTED_MAIL);

    const text = await operationText(handle, port, SEARCH, ErrorCode.IMAP_OPERATION_FAILED, {
      account: "ops@example.com",
    });

    expect(text).toBe(`IMAP operation 'authenticate' failed: ${MAIL_HOST}:${port}`);
  });

  it.each<[string, string, Record<string, unknown>, string]>([
    [
      "a SEARCH date that is none quotes it as sent",
      `u:${VALUE_DATE}`,
      { kind: "search", since: VALUE_DATE },
      `invalid IMAP SEARCH date: ${VALUE_DATE}`,
    ],
    [
      "a fetch without a UID: the fixed words as they stand",
      `u:${WORD_REQUIRED}`,
      { kind: "fetch", uids: [], parts: "envelope" },
      "at least one UID is required",
    ],
    [
      "a UID that is none: the number as sent",
      `u:${VALUE_UID}`,
      { kind: "fetch", uids: [-Number(VALUE_UID)], parts: "envelope" },
      `invalid IMAP UID: -${VALUE_UID}`,
    ],
    [
      "a flag to add that is none quotes it as sent",
      `u:${VALUE_FLAG}`,
      { kind: "store", uids: [1], add_flags: ["\\Seen", `${VALUE_FLAG}*`] },
      `invalid IMAP flag: ${VALUE_FLAG}*`,
    ],
    [
      "a flag to remove that is none quotes it as sent",
      `u:${VALUE_FLAG}`,
      { kind: "store", uids: [1], remove_flags: [`${VALUE_FLAG}*`] },
      `invalid IMAP flag: ${VALUE_FLAG}*`,
    ],
    [
      "fetch parts the client does not know quote them as sent",
      `u:${VALUE_PARTS}`,
      { kind: "fetch", uids: [1], parts: VALUE_PARTS },
      `unsupported IMAP fetch parts: ${VALUE_PARTS}`,
    ],
  ])("%s", async (_title, secret, operation, message) => {
    const port = await mailServer(true, IMAP_GREETING, imapAnswer());
    const handle = await mailSecret(secret, TRUSTED_MAIL);

    const text = await operationText(handle, port, operation, ErrorCode.INVALID_INPUT);

    expect(text).toBe(message);
  });

  it("a server's reply that holds the password is not in the message", async () => {
    const port = await mailServer(
      true,
      IMAP_GREETING,
      imapAnswer({ LOGIN: (tag) => `${tag} NO [AUTHENTICATIONFAILED] ${PW_FIXTURE} rejected\r\n` }),
    );
    const handle = await mailSecret(REPLY_SECRET, TRUSTED_MAIL);

    const text = await operationText(handle, port, SEARCH);

    expectAbsent(text, PW_FIXTURE);
    expect(text).toBe(`IMAP operation 'login' failed: ${MAIL_HOST}:${port}`);
  });
});

const MCP_NODE = process.execPath;
const WORD_MATCH = "match";
const WORD_PRIVATE = "private";
const WORD_PROTOCOL = "protocol";
const WORD_SPAWN = "spawn";
const WORD_CONNECT = "connect";
const WORD_EXITED = "exited";
const WORD_CLOSED = "closed";
const WORD_TIMED = "timed";
const WORD_SESSION = "session";
const WORD_SUPERSEDED = "superseded";

/** Answers `initialize`, then ends itself once the client says it is initialized. */
const SELF_ENDING_SERVER = `
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") {
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: {
      protocolVersion: m.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "harpoc-self-ending", version: "1.0.0" },
    }}) + "\\n");
  } else if (m.method === "notifications/initialized") {
    process.exit(3);
  }
});
`;

/** The job wrapper's own failure, faked by the payload: its marker line, then its reserved exit. */
function wrapperFailingServer(line: string, onCall: boolean): string {
  const fail = `process.stderr.write(${JSON.stringify(line)}); process.exit(9009);`;
  if (!onCall) return fail;
  return `
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (raw) => {
  let m; try { m = JSON.parse(raw); } catch { return; }
  if (m.method === "initialize") {
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: {
      protocolVersion: m.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "harpoc-wrapper-failing", version: "1.0.0" },
    }}) + "\\n");
  } else if (m.method === "tools/call") {
    ${fail}
  }
});
`;
}

describe("the MCP context's sites", () => {
  const spies: MockInstance[] = [];
  const downstreams: Server[] = [];

  afterEach(async () => {
    for (const spy of spies.splice(0)) spy.mockRestore();
    await mcpRegistry().closeAll("test_cleanup");
    for (const server of downstreams.splice(0)) {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  function mcpRegistry(): McpConnectionRegistry {
    return (engine as unknown as { mcpRegistry: McpConnectionRegistry }).mcpRegistry;
  }

  async function mcpSecret(
    value: string,
    config: McpServerConfigInput,
    policy: InjectionPolicyInput = {},
  ): Promise<string> {
    const handle = await storeSecret("srv", value);
    await engine.setInjectionPolicy(
      handle,
      { command_allowlist: [MCP_NODE], ...policy },
      { acknowledge_interpreters: true },
    );
    await engine.setMcpServerConfig(handle, config);
    return handle;
  }

  function stdioServer(serverName: string, script = TEST_SERVER): McpServerConfigInput {
    return {
      server_name: serverName,
      transport: "stdio",
      command: MCP_NODE,
      args: ["-e", script],
      env_var: "DOWNSTREAM_TOKEN",
    };
  }

  function httpServer(serverName: string, url: string): McpServerConfigInput {
    return { server_name: serverName, transport: "http", url };
  }

  function mcpUse(server: string, tool = "echo", extra: Record<string, unknown> = {}): unknown {
    return { type: "mcp", server, tool, ...extra };
  }

  function rejectStart(err: Error): void {
    spies.push(vi.spyOn(StdioChildTransport.prototype, "start").mockRejectedValue(err));
  }

  /** The launch reads as the job tier's, as it does under the win32 job wrapper. */
  function underJobTier(): void {
    const start = StdioChildTransport.prototype.start;
    spies.push(
      vi.spyOn(StdioChildTransport.prototype, "start").mockImplementation(function (
        this: StdioChildTransport,
      ) {
        const self = this as unknown as { params: Record<string, unknown> };
        self.params = { ...self.params, treeKill: "job" };
        return start.call(this);
      }),
    );
  }

  /** `then` runs between this call's connect and the registry's publish. */
  function beforePublish(
    then: (
      entry: McpConnectionEntry,
      secretId: string,
      acquire: McpConnectionRegistry["acquire"],
    ) => Promise<void>,
  ): void {
    const registry = mcpRegistry();
    const acquire = registry.acquire.bind(registry);
    spies.push(
      vi.spyOn(registry, "acquire").mockImplementationOnce((secretId, factory) =>
        acquire(secretId, async () => {
          const entry = await factory();
          await then(entry, secretId, acquire);
          return entry;
        }),
      ),
    );
  }

  async function listen(
    handler: (req: IncomingMessage, res: ServerResponse) => void,
  ): Promise<string> {
    const server = createServer(handler);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    downstreams.push(server);
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`;
  }

  /** A legacy-era downstream over Streamable HTTP; `onCall` answers a tool call in its place. */
  async function legacyDownstream(onCall?: (res: ServerResponse) => void): Promise<string> {
    const downstream = new McpServer({ name: "use-error-text", version: "1.0.0" });
    downstream.registerTool("echo", { description: "Echo" }, async () => ({
      content: [{ type: "text" as const, text: "never reached" }],
    }));
    const transport = new NodeStreamableHTTPServerTransport({ sessionIdGenerator: randomUUID });
    await downstream.connect(transport);
    return listen((req, res) => {
      if (req.method !== "POST") {
        void transport.handleRequest(req, res);
        return;
      }
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { method?: string };
        if (parsed.method === "tools/call" && onCall !== undefined) onCall(res);
        else void transport.handleRequest(req, res, parsed);
      });
    });
  }

  it("a server name that does not match: the name as sent, the configured one outside text", async () => {
    const handle = await mcpSecret(WORD_MATCH, stdioServer(`${WORD_MATCH}-cfg`));

    const text = await refusedText(handle, mcpUse(WORD_MATCH), ErrorCode.MCP_SERVER_MISMATCH);

    expect(text).toBe(
      `MCP server '${WORD_MATCH}' does not match configured server '[REDACTED]-cfg'`,
    );
  });

  it("an endpoint off the URL allowlist: the stored URL outside text", async () => {
    const handle = await mcpSecret(
      WORD_ALLOWLIST,
      httpServer("srv", `https://${WORD_ALLOWLIST}.example/mcp`),
    );

    const text = await refusedText(handle, mcpUse("srv"), ErrorCode.URL_NOT_ALLOWED);

    expect(text).toBe("URL not in secret allowlist: https://[REDACTED].example/mcp");
  });

  it("the endpoint's check before the connect: the stored host outside text", async () => {
    const handle = await mcpSecret(WORD_PRIVATE, httpServer("srv", "https://private.example/mcp"), {
      url_allowlist: ["https://private.example/*"],
    });
    dnsLookupMock.mockResolvedValue([{ address: VALUE_ADDRESS, family: 4 }]);

    const text = await refusedText(handle, mcpUse("srv"), ErrorCode.SSRF_BLOCKED);

    expect(text).toBe(`SSRF blocked: [REDACTED].example resolves to private IP ${VALUE_ADDRESS}`);
  });

  it("the endpoint's check on each request: the stored host outside text", async () => {
    const handle = await mcpSecret(WORD_PRIVATE, httpServer("srv", "https://private.example/mcp"), {
      url_allowlist: ["https://private.example/*"],
    });
    dnsLookupMock
      .mockResolvedValueOnce([{ address: "8.8.8.8", family: 4 }])
      .mockResolvedValueOnce([{ address: VALUE_ADDRESS, family: 4 }]);

    const text = await refusedText(handle, mcpUse("srv"), ErrorCode.SSRF_BLOCKED);

    expect(text).toBe(`SSRF blocked: [REDACTED].example resolves to private IP ${VALUE_ADDRESS}`);
    expect(dnsLookupMock).toHaveBeenCalledTimes(2);
  });

  it("a redirect: the status a number, the words as they stand", async () => {
    const url = await listen((_req, res) => {
      res.writeHead(307, { location: "http://127.0.0.1:1/elsewhere" });
      res.end();
    });
    const handle = await mcpSecret(WORD_REDIRECTS, httpServer("srv", url), {
      url_allowlist: [`${new URL(url).origin}/*`],
    });

    const text = await refusedText(handle, mcpUse("srv"), ErrorCode.REDIRECT_POLICY_VIOLATION);

    expect(text).toBe(
      "Downstream MCP server redirected (307); redirects are refused — configure the final endpoint URL",
    );
  });

  it("a protocol the downstream does not offer: the revision a token, the server outside text", async () => {
    const url = await legacyDownstream();
    const handle = await mcpSecret(
      WORD_PROTOCOL,
      { ...httpServer(WORD_PROTOCOL, url), protocol: "2026-07-28" },
      { url_allowlist: [`${new URL(url).origin}/*`] },
    );

    const err = await expectVaultError(
      () => engine.useSecret(handle, mcpUse(WORD_PROTOCOL) as UseSecretAction),
      ErrorCode.MCP_CONNECT_FAILED,
    );

    expect(err.message).toBe(
      "Failed to connect to MCP server '[REDACTED]': protocol 2026-07-28 is not offered by the downstream server",
    );
    expect(err.details).toStrictEqual({ server: "[REDACTED]" });
  });

  it("a failed spawn names its code and no file", async () => {
    const handle = await mcpSecret(WORD_SPAWN, stdioServer("S"));
    rejectStart(
      Object.assign(new Error("spawn C:\\wrapper.exe ENOENT"), {
        code: "ENOENT",
        syscall: "spawn C:\\wrapper.exe",
      }),
    );

    const text = await refusedText(handle, mcpUse("S"), ErrorCode.MCP_CONNECT_FAILED);

    expect(text.includes("wrapper")).toBe(false);
    expect(text).toBe("Failed to connect to MCP server 'S': spawn failed (ENOENT)");
  });

  it("any other failed connect: its message outside text", async () => {
    const handle = await mcpSecret(WORD_CONNECT, stdioServer("srv"));
    rejectStart(
      Object.assign(new Error(`${WORD_CONNECT} ECONNREFUSED by the child`), {
        code: "ECONNREFUSED",
        syscall: WORD_CONNECT,
      }),
    );

    const text = await refusedText(handle, mcpUse("srv"), ErrorCode.MCP_CONNECT_FAILED);

    expect(text).toBe(
      "Failed to connect to MCP server 'srv': [REDACTED] ECONNREFUSED by the child",
    );
  });

  it.runIf(process.platform === "win32")(
    "the job wrapper's failure at the connect: its line outside text",
    async () => {
      underJobTier();
      const handle = await mcpSecret(
        WORD_SPAWN,
        stdioServer(
          "srv",
          wrapperFailingServer(`harpoc-job: CreateProcess ${WORD_SPAWN} error`, false),
        ),
      );

      const text = await refusedText(handle, mcpUse("srv"), ErrorCode.MCP_CONNECT_FAILED);

      expect(text).toBe(
        "Failed to connect to MCP server 'srv': spawn failed: harpoc-job: CreateProcess [REDACTED] error",
      );
    },
  );

  it.runIf(process.platform === "win32")(
    "the job wrapper's failure under a call: its line outside text",
    async () => {
      underJobTier();
      const handle = await mcpSecret(
        WORD_SPAWN,
        stdioServer(
          "srv",
          wrapperFailingServer(`harpoc-job: assign ${WORD_SPAWN} failed: 5`, true),
        ),
      );

      const text = await refusedText(handle, mcpUse("srv"), ErrorCode.MCP_CONNECT_FAILED);

      expect(text).toBe(
        "Failed to connect to MCP server 'srv': spawn failed: harpoc-job: assign [REDACTED] failed: 5",
      );
    },
  );

  it("a crash under a call: the server outside text, the exit a number", async () => {
    const handle = await mcpSecret(WORD_EXITED, stdioServer(WORD_EXITED));

    const err = await expectVaultError(
      () => engine.useSecret(handle, mcpUse(WORD_EXITED, "crash") as UseSecretAction),
      ErrorCode.MCP_SERVER_CRASHED,
    );

    expect(err.message).toBe("MCP server '[REDACTED]' exited unexpectedly");
    expect(err.details).toStrictEqual({ server: "[REDACTED]", exit_code: 7, signal: null });
  });

  it("a connection closed under a call: the server outside text", async () => {
    const handle = await mcpSecret(WORD_CLOSED, stdioServer(`${WORD_CLOSED}-srv`));
    const secretId = await engine.resolveSecretId(handle);
    let called: () => void = () => undefined;
    const sent = new Promise<void>((resolve) => (called = resolve));
    const send = StdioChildTransport.prototype.send;
    spies.push(
      vi.spyOn(StdioChildTransport.prototype, "send").mockImplementation(function (
        this: StdioChildTransport,
        message,
      ) {
        if ((message as { method?: string }).method === "tools/call") called();
        return send.call(this, message);
      }),
    );
    const use = engine.useSecret(handle, mcpUse(`${WORD_CLOSED}-srv`, "slow") as UseSecretAction);
    use.catch(() => undefined);
    await sent;

    await mcpRegistry().terminate(secretId, "test_terminate");

    const err = await expectVaultError(() => use, ErrorCode.MCP_CONNECT_FAILED);
    expect(err.message).toBe("Failed to connect to MCP server '[REDACTED]-srv': connection closed");
  });

  it("a call that times out: the server outside text", async () => {
    const handle = await mcpSecret(WORD_TIMED, stdioServer(WORD_TIMED));

    const err = await expectVaultError(
      () =>
        engine.useSecret(
          handle,
          mcpUse(WORD_TIMED, "slow", { timeout_ms: 300 }) as UseSecretAction,
        ),
      ErrorCode.MCP_TIMEOUT,
    );

    expect(err.message).toBe("MCP tool call to server '[REDACTED]' timed out");
    expect(err.details).toStrictEqual({ server: "[REDACTED]" });
  });

  it("the downstream's JSON-RPC error: its message outside text", async () => {
    const handle = await mcpSecret(WORD_PROTOCOL, stdioServer("srv"));

    const text = await refusedText(
      handle,
      mcpUse("srv", WORD_PROTOCOL),
      ErrorCode.MCP_PROTOCOL_ERROR,
    );

    expect(text).toBe("MCP protocol error from server 'srv': Unknown tool: [REDACTED]");
  });

  it("the SDK's error for a failed request: its message outside text", async () => {
    const url = await legacyDownstream((res) => {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end(`upstream said ${WORD_PROTOCOL}`);
    });
    const handle = await mcpSecret(WORD_PROTOCOL, httpServer("srv", url), {
      url_allowlist: [`${new URL(url).origin}/*`],
    });

    const text = await refusedText(handle, mcpUse("srv"), ErrorCode.MCP_PROTOCOL_ERROR);

    expect(text).toBe(
      "MCP protocol error from server 'srv': Error POSTing to endpoint: upstream said [REDACTED]",
    );
  });

  it("any other failed call: its message outside text", async () => {
    const handle = await mcpSecret(WORD_PROTOCOL, stdioServer("srv"));
    const send = StdioChildTransport.prototype.send;
    spies.push(
      vi.spyOn(StdioChildTransport.prototype, "send").mockImplementation(function (
        this: StdioChildTransport,
        message,
      ) {
        if ((message as { method?: string }).method !== "tools/call")
          return send.call(this, message);
        return Promise.reject(new Error(`stdin write failed after ${WORD_PROTOCOL}`));
      }),
    );

    const text = await refusedText(handle, mcpUse("srv"), ErrorCode.MCP_PROTOCOL_ERROR);

    expect(text).toBe("MCP protocol error from server 'srv': stdin write failed after [REDACTED]");
  });

  it("a child dead before the publish: the server outside text, the exit a number", async () => {
    const handle = await mcpSecret(WORD_EXITED, stdioServer(WORD_EXITED, SELF_ENDING_SERVER));
    beforePublish(async (entry) => {
      await vi.waitFor(() => expect(entry.stdioTransport?.exitInfo).not.toBeNull(), {
        timeout: 5_000,
      });
    });

    const err = await expectVaultError(
      () => engine.useSecret(handle, mcpUse(WORD_EXITED) as UseSecretAction),
      ErrorCode.MCP_SERVER_CRASHED,
    );

    expect(err.message).toBe("MCP server '[REDACTED]' exited unexpectedly");
    expect(err.details).toStrictEqual({ server: "[REDACTED]", exit_code: 3, signal: null });
  });

  it("a session ended under the connect: the server outside text", async () => {
    const handle = await mcpSecret(WORD_SESSION, stdioServer(WORD_SESSION));
    beforePublish(async () => {
      await mcpRegistry().closeAll("test_session_end");
    });

    const err = await expectVaultError(
      () => engine.useSecret(handle, mcpUse(WORD_SESSION) as UseSecretAction),
      ErrorCode.MCP_CONNECT_FAILED,
    );

    expect(err.message).toBe(
      "Failed to connect to MCP server '[REDACTED]': vault session ended while connecting",
    );
    expect(err.details).toStrictEqual({ server: "[REDACTED]" });
  });

  it("a connect superseded by another: the server outside text", async () => {
    const handle = await mcpSecret(WORD_SUPERSEDED, stdioServer(WORD_SUPERSEDED));
    beforePublish(async (entry, secretId, acquire) => {
      void mcpRegistry().terminate(secretId, "test_superseded");
      await acquire(secretId, () =>
        Promise.resolve({
          ...entry,
          client: { close: () => Promise.resolve() } as McpConnectionEntry["client"],
          stdioTransport: undefined,
          dispose: undefined,
          state: "connecting",
        }),
      );
    });

    const err = await expectVaultError(
      () => engine.useSecret(handle, mcpUse(WORD_SUPERSEDED) as UseSecretAction),
      ErrorCode.MCP_CONNECT_FAILED,
    );

    expect(err.message).toBe(
      "Failed to connect to MCP server '[REDACTED]': superseded while connecting",
    );
    expect(err.details).toStrictEqual({ server: "[REDACTED]" });
  });

  it.runIf(process.platform === "win32")(
    "no job wrapper for a strict tree exit: the reason's words as they stand",
    async () => {
      const handle = await mcpSecret(WORD_WINDOWS, stdioServer("srv"), { strict_tree_exit: true });
      const reason = vaultText`no job wrapper on this host`;
      forceJobWrapperUnavailableForTests(reason);
      try {
        const text = await refusedText(
          handle,
          mcpUse("srv"),
          ErrorCode.STRICT_TREE_EXIT_UNAVAILABLE,
        );

        expect(text).toBe(VaultError.strictTreeExitUnavailable(reason).message);
      } finally {
        forceJobWrapperUnavailableForTests(null);
      }
    },
  );
});
