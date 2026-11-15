import { lstatSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ErrorCode, maxUnixSocketPathBytes } from "@harpoc/shared";
import { EphemeralSshAgent } from "./index.js";
import { expectVaultError } from "@harpoc/test-utils";

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, mkdtempSync: vi.fn(actual.mkdtempSync) };
});

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "__fixtures__", "ssh");
const KEY_PEM = readFileSync(join(FIXTURES, "ed25519_openssh"), "utf8");
const REAL_PLATFORM = process.platform;

/** What the agent adds to the temporary directory's path: `<sep>harpoc-agent-XXXXXX<sep>agent.sock`. */
const AGENT_SOCKET_SUFFIX_BYTES = Buffer.byteLength(`${sep}harpoc-agent-XXXXXX${sep}agent.sock`);

let saved: { TMPDIR?: string; TMP?: string; TEMP?: string } | undefined;
let temp: string | undefined;

/** The platform `EphemeralSshAgent.start` reads by default, stubbed for one row and put back after it. */
function stubPlatform(value: NodeJS.Platform): void {
  Object.defineProperty(process, "platform", { value, configurable: true });
}

/**
 * A new directory os.tmpdir() reads for the row (TEMP/TMP on win32, TMPDIR on POSIX), its length
 * chosen so the agent's socket path under it is exactly `bytes` bytes.
 */
function tempDirForSocketOf(bytes: number): string {
  const prefix = join(tmpdir(), "harpoc-");
  const fill = bytes - AGENT_SOCKET_SUFFIX_BYTES - Buffer.byteLength(prefix) - 6;
  const dir = mkdtempSync(`${prefix}${"x".repeat(fill)}`);
  temp = dir;
  expect(Buffer.byteLength(dir) + AGENT_SOCKET_SUFFIX_BYTES).toBe(bytes);
  saved = { TMPDIR: process.env.TMPDIR, TMP: process.env.TMP, TEMP: process.env.TEMP };
  process.env.TMPDIR = dir;
  process.env.TMP = dir;
  process.env.TEMP = dir;
  return dir;
}

/** The socket directories the agent asked `mkdtempSync` for in this row. */
function agentDirsAsked(): string[] {
  return vi
    .mocked(mkdtempSync)
    .mock.calls.map(([prefix]) => String(prefix))
    .filter((prefix) => basename(prefix) === "harpoc-agent-");
}

function socketPathRefusal(bytes: number, max: number): string {
  return `Ephemeral ssh-agent failed: the agent's socket path is ${String(bytes)} bytes, over the ${String(max)} a Unix socket address holds`;
}

afterEach(() => {
  stubPlatform(REAL_PLATFORM);
  vi.mocked(mkdtempSync).mockClear();
  if (saved !== undefined) {
    if (saved.TMPDIR === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = saved.TMPDIR;
    if (saved.TMP === undefined) delete process.env.TMP;
    else process.env.TMP = saved.TMP;
    if (saved.TEMP === undefined) delete process.env.TEMP;
    else process.env.TEMP = saved.TEMP;
    saved = undefined;
  }
  if (temp !== undefined) {
    rmSync(temp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    temp = undefined;
  }
});

describe("EphemeralSshAgent.start — the socket path's bound", () => {
  // On a win32 host the agent serves a named pipe, which no socket-path bound applies to.
  it.skipIf(process.platform === "win32")(
    "darwin's bound on any POSIX host (the platform passed): a 104-byte socket path is refused SSH_AGENT_FAILED naming its length and the 103, and nothing is created",
    async () => {
      const dir = tempDirForSocketOf(104);

      const err = await expectVaultError(
        () => EphemeralSshAgent.start(KEY_PEM, "darwin"),
        ErrorCode.SSH_AGENT_FAILED,
      );
      expect(err.message).toBe(socketPathRefusal(104, 103));
      expect(agentDirsAsked()).toEqual([]);
      expect(readdirSync(dir)).toEqual([]);
    },
  );

  it("the platform defaults to process.platform: stubbed to darwin, a 104-byte socket path is refused naming the 103, and nothing is created", async () => {
    const dir = tempDirForSocketOf(104);
    stubPlatform("darwin");

    const err = await expectVaultError(
      () => EphemeralSshAgent.start(KEY_PEM),
      ErrorCode.SSH_AGENT_FAILED,
    );
    expect(err.message).toBe(socketPathRefusal(104, 103));
    expect(agentDirsAsked()).toEqual([]);
    expect(readdirSync(dir)).toEqual([]);
  });

  // A Unix socket path exists on POSIX only: on win32 the agent serves a named pipe.
  it.skipIf(process.platform === "win32")(
    "refuses a socket path one byte over this platform's bound (107; darwin 103), and nothing is created (POSIX)",
    async () => {
      const bound = maxUnixSocketPathBytes(process.platform);
      const dir = tempDirForSocketOf(bound + 1);

      const err = await expectVaultError(
        () => EphemeralSshAgent.start(KEY_PEM),
        ErrorCode.SSH_AGENT_FAILED,
      );
      expect(err.message).toBe(socketPathRefusal(bound + 1, bound));
      expect(agentDirsAsked()).toEqual([]);
      expect(readdirSync(dir)).toEqual([]);
    },
  );

  it.skipIf(process.platform === "win32")(
    "starts on a socket path of exactly this platform's bound (107; darwin 103), and dispose() leaves nothing (POSIX)",
    async () => {
      const bound = maxUnixSocketPathBytes(process.platform);
      const dir = tempDirForSocketOf(bound);

      const agent = await EphemeralSshAgent.start(KEY_PEM);
      try {
        expect(Buffer.byteLength(agent.authSock)).toBe(bound);
        expect(lstatSync(agent.authSock).isSocket()).toBe(true);
      } finally {
        agent.dispose();
      }
      expect(readdirSync(dir)).toEqual([]);
    },
  );
});

describe("EphemeralSshAgent.start — the platform passed names the bound alone", () => {
  it.runIf(process.platform === "win32")(
    "on a win32 host, passing a POSIX platform still serves the named pipe and creates no directory",
    async () => {
      const agent = await EphemeralSshAgent.start(KEY_PEM, "linux");
      try {
        expect(agent.authSock.startsWith("\\\\.\\pipe\\harpoc-ssh-")).toBe(true);
        expect(agentDirsAsked()).toEqual([]);
      } finally {
        agent.dispose();
      }
    },
  );

  it.skipIf(process.platform === "win32")(
    "on a POSIX host, passing win32 still binds the socket in its temporary directory (POSIX)",
    async () => {
      const agent = await EphemeralSshAgent.start(KEY_PEM, "win32");
      try {
        expect(lstatSync(agent.authSock).isSocket()).toBe(true);
        expect(basename(agent.authSock)).toBe("agent.sock");
        expect(dirname(dirname(agent.authSock))).toBe(tmpdir());
        expect(basename(dirname(agent.authSock)).startsWith("harpoc-agent-")).toBe(true);
      } finally {
        agent.dispose();
      }
    },
  );
});
