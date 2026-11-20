import { generateKeyPairSync } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, sep } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionConfig, InjectionPolicy, SftpAction } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { controlledPathDirs } from "./allowlist.js";
import { agentSocketAccepts } from "./__fixtures__/agent-socket.js";
import { resolveNativeSshClient } from "./__fixtures__/native-ssh-client.js";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { executeSftpAction } from "./sftp-injector.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
import { system32Path } from "../win32-paths.js";

vi.mock("./spawn-captured.js", () => ({ spawnCaptured: vi.fn() }));
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, mkdtempSync: vi.fn(actual.mkdtempSync) };
});

// On Windows the ephemeral agent listens on a named pipe, which only the native
// Win32-OpenSSH client consumes through SSH_AUTH_SOCK; an MSYS build (the
// Git-bundled ssh a Git-Bash PATH resolves first) finds no agent and is refused
// before any spawn (D58). The sftp injector resolves the bare name against the process
// PATH itself, so the native directory has to lead there, not only in the allowlist
// entry this suite pins (ssh-live-auth.test.ts pins the same client for the same reason).
if (process.platform === "win32") {
  const nativeSshDir = system32Path("OpenSSH");
  process.env.PATH = [
    nativeSshDir,
    ...controlledPathDirs().filter((d) => d.toLowerCase() !== nativeSshDir.toLowerCase()),
  ].join(delimiter);
}

const SFTP = resolveNativeSshClient("sftp");
// Skipped where no native sftp client resolves (an MSYS/Cygwin build reads as absent).
const describeSftp = describe.skipIf(SFTP === null);

it("ssh-live tier: required legs fail instead of skipping when sftp is unresolvable", () => {
  if (SFTP === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no sftp client resolves',
    );
  }
});

const OK_RESULT: SpawnCapturedResult = {
  exit_code: 0,
  stdout: "",
  stderr: "",
  timed_out: false,
  truncated: false,
  signal: null,
  spawn_failed: false,
  redacted: false,
};

function makeKeyPem(): string {
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return privateKey;
}

function policy(overrides: Partial<InjectionPolicy> = {}): InjectionPolicy {
  return {
    url_allowlist: [],
    command_allowlist: [],
    env_allowlist: [],
    host_allowlist: [],
    response_mode: "filtered",
    response_header_allowlist: [],
    network_isolation: false,
    fs_isolation: false,
    smtp_recipient_allowlist: [],
    imap_read_only: false,
    strict_tree_exit: false,
    proxy: false,
    ssh_agent_socket: false,
    local_dirs: [],
    ...overrides,
  };
}

const SFTP_CONFIG: ConnectionConfig = {
  ssh: { known_hosts: ["deploy.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
};
const PEM_ARMOR = "PRIVATE KEY";

function allowedPolicy(overrides: Partial<InjectionPolicy> = {}): InjectionPolicy {
  return policy({
    host_allowlist: ["deploy.example.com"],
    command_allowlist: [SFTP as string],
    ...overrides,
  });
}

const LIST_ACTION: SftpAction = {
  type: "sftp",
  host: "deploy.example.com",
  user: "deploy",
  operation: "list",
  remote_path: "/srv/reports",
};

const UPLOAD_ACTION: SftpAction = {
  type: "sftp",
  host: "deploy.example.com",
  user: "deploy",
  operation: "upload",
  remote_path: "/srv/report.pdf",
};

const DOWNLOAD_ACTION: SftpAction = {
  type: "sftp",
  host: "deploy.example.com",
  user: "deploy",
  operation: "download",
  remote_path: "/srv/report.pdf",
};

const ACTION = { upload: UPLOAD_ACTION, download: DOWNLOAD_ACTION } as const;

const TOO_LONG = "sftp paths are too long for one batch command";
const NO_BACKSLASH = "sftp remote path must not contain a backslash";
const TRAILING_BACKSLASH = "sftp path must not end with '\\' (would merge with the closing quote)";

const TRANSFERS = ["upload", "download"] as const;
const BACKSLASH_REMOTES = ["dir\\file", "a\\\\b"] as const;
const GLOB_REMOTES = ["/srv/report*.pdf", "/srv/report?.pdf", "/srv/report[1].pdf"] as const;

let localDir: string;
let listedDir: string;
let listedFile: string;
let outsideFile: string;

beforeAll(() => {
  // `.native` like the injector's realpath: it expands a win32 short name (C:\Users\RUNNER~1 on CI).
  localDir = realpathSync.native(mkdtempSync(join(tmpdir(), "harpoc-sftp-local-")));
  listedDir = join(localDir, "listed");
  listedFile = join(listedDir, "report.pdf");
  outsideFile = join(localDir, "outside", "report.pdf");
  for (const dir of [listedDir, join(listedDir, "sub"), join(localDir, "outside")]) mkdirSync(dir);
  writeFileSync(listedFile, "report");
  writeFileSync(outsideFile, "outside");
});

afterAll(() => {
  rmSync(localDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

function batchLine(operation: SftpAction["operation"], remote: string): string {
  switch (operation) {
    case "upload":
      return `put "${listedFile}" "${remote}"\n`;
    case "download":
      return `get "${remote}" "${listedFile}"\n`;
    case "list":
      return `ls -l "${remote}"\n`;
  }
}

/** A remote path that makes the operation's batch line `bytes` long, its newline included. */
function remoteForLineOf(operation: SftpAction["operation"], bytes: number): string {
  return `/${"r".repeat(bytes - Buffer.byteLength(batchLine(operation, "/")))}`;
}

function actionOn(operation: SftpAction["operation"], remote: string): SftpAction {
  return operation === "list"
    ? { ...LIST_ACTION, remote_path: remote }
    : { ...ACTION[operation], remote_path: remote, local_path: listedFile };
}

describeSftp("executeSftpAction spawn hardening (sftp resolvable)", () => {
  const spawnMock = vi.mocked(spawnCaptured);

  beforeEach(() => {
    spawnMock.mockReset();
    spawnMock.mockResolvedValue(OK_RESULT);
  });

  it("spawns sftp with strict host-key hardening, batch mode and no shell", async () => {
    const keyPem = makeKeyPem();
    const result = await executeSftpAction(
      LIST_ACTION,
      new Uint8Array(Buffer.from(keyPem)),
      allowedPolicy(),
      SFTP_CONFIG,
    );

    expect(result.result.exit_code).toBe(0);
    expect(result.sanitized).toBe(false);
    expect(spawnMock).toHaveBeenCalledOnce();
    const [command, args, opts] = spawnMock.mock.calls[0] as [
      string,
      string[],
      { env: Record<string, string>; redact?: string[] },
    ];

    expect(command).toBe(SFTP);
    expect(args).toContain("StrictHostKeyChecking=yes");
    expect(args).toContain("IdentitiesOnly=yes");
    expect(args).toContain("BatchMode=yes");
    // sftp's own belt-and-suspenders batch-mode flag, distinct from the `-o
    // BatchMode=yes` two-token form sshHardeningArgs already contributes.
    expect(args).toContain("-oBatchMode=yes");

    const bIdx = args.indexOf("-b");
    expect(bIdx).toBeGreaterThan(-1);
    const batchFile = args[bIdx + 1] as string;
    expect(batchFile.length).toBeGreaterThan(0);

    // "-oBatchMode=yes -b <batchFile> user@host" is the exact argv tail — no
    // `-l`, no `--`: sftp has no separate user flag, and paths never reach
    // argv at all (they live inside the batch file).
    expect(args).toEqual([
      "-F",
      "none",
      "-o",
      "StrictHostKeyChecking=yes",
      "-o",
      expect.stringMatching(/^UserKnownHostsFile="[^"]*harpoc-ssh-[^\\/"]+[\\/]known_hosts"$/),
      "-o",
      "GlobalKnownHostsFile=none",
      "-o",
      "IdentitiesOnly=yes",
      "-i",
      expect.stringMatching(/harpoc-ssh-id-[^\\/]+[\\/]identity\.pub$/),
      "-o",
      "BatchMode=yes",
      "-o",
      "PasswordAuthentication=no",
      "-o",
      "ConnectTimeout=30",
      "-oBatchMode=yes",
      "-b",
      batchFile,
      "deploy@deploy.example.com",
    ]);

    expect(opts.env.SSH_AUTH_SOCK).toBeTruthy();
    expect(args.every((a) => !a.includes(PEM_ARMOR))).toBe(true);
    expect(opts.redact).toContain(keyPem);
  });

  it("spawns sftp with a built environment, not the vault's own", async () => {
    process.env.HARPOC_T14_SFTP_AMBIENT = "ambient-value";
    process.env.HARPOC_T14_SFTP_ALLOWED = "allowed-value";
    try {
      await executeSftpAction(
        LIST_ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        allowedPolicy({ env_allowlist: ["HARPOC_T14_SFTP_ALLOWED"] }),
        SFTP_CONFIG,
      );

      const [, , opts] = spawnMock.mock.calls[0] as [
        string,
        string[],
        { env: Record<string, string> },
      ];
      expect(opts.env.HARPOC_T14_SFTP_AMBIENT).toBeUndefined();
      expect(opts.env.HARPOC_T14_SFTP_ALLOWED).toBe("allowed-value");

      const expected = new Set([
        "PATH",
        ...(process.platform === "win32" ? ["SystemRoot", "ProgramData"] : []),
        "SSH_AUTH_SOCK",
        "HARPOC_T14_SFTP_ALLOWED",
      ]);
      expect(Object.keys(opts.env).filter((k) => !expected.has(k))).toEqual([]);
    } finally {
      delete process.env.HARPOC_T14_SFTP_AMBIENT;
      delete process.env.HARPOC_T14_SFTP_ALLOWED;
    }
  });

  it("passes a non-22 port as -P ahead of the batch-mode flags", async () => {
    await executeSftpAction(
      { ...LIST_ACTION, port: 2222 },
      new Uint8Array(Buffer.from(makeKeyPem())),
      allowedPolicy(),
      SFTP_CONFIG,
    );
    const [, args] = spawnMock.mock.calls[0] as [string, string[], { env: Record<string, string> }];
    expect(args).toEqual([
      "-F",
      "none",
      "-o",
      "StrictHostKeyChecking=yes",
      "-o",
      expect.stringMatching(/^UserKnownHostsFile="[^"]*harpoc-ssh-[^\\/"]+[\\/]known_hosts"$/),
      "-o",
      "GlobalKnownHostsFile=none",
      "-o",
      "IdentitiesOnly=yes",
      "-i",
      expect.stringMatching(/harpoc-ssh-id-[^\\/]+[\\/]identity\.pub$/),
      "-o",
      "BatchMode=yes",
      "-o",
      "PasswordAuthentication=no",
      "-o",
      "ConnectTimeout=30",
      "-P",
      "2222",
      "-oBatchMode=yes",
      "-b",
      expect.stringMatching(/harpoc-sftp-batch-[^\\/]+[\\/]batch$/),
      "deploy@deploy.example.com",
    ]);
  });

  it("removes the batch file after a successful invocation", async () => {
    let batchPath = "";
    spawnMock.mockImplementation((_cmd, args) => {
      batchPath = args[args.indexOf("-b") + 1] as string;
      return Promise.resolve(OK_RESULT);
    });

    await executeSftpAction(
      LIST_ACTION,
      new Uint8Array(Buffer.from(makeKeyPem())),
      allowedPolicy(),
      SFTP_CONFIG,
    );

    expect(existsSync(batchPath)).toBe(false);
  });

  it("removes the batch file even when the spawn seam throws", async () => {
    let batchPath = "";
    spawnMock.mockImplementation((_cmd, args) => {
      batchPath = args[args.indexOf("-b") + 1] as string;
      return Promise.reject(new Error("spawn boom"));
    });

    await expect(
      executeSftpAction(
        LIST_ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        allowedPolicy(),
        SFTP_CONFIG,
      ),
    ).rejects.toThrow("spawn boom");

    expect(batchPath.length).toBeGreaterThan(0);
    expect(existsSync(batchPath)).toBe(false);
  });

  // I8: the agent's socket is serving at spawn and gone once the call settles.
  it("disposes the agent's socket once the call resolves", async () => {
    let sock = "";
    let servingAtSpawn = false;
    spawnMock.mockImplementation(async (_cmd, _args, opts) => {
      sock = opts.env.SSH_AUTH_SOCK ?? "";
      servingAtSpawn = await agentSocketAccepts(sock);
      return OK_RESULT;
    });

    await executeSftpAction(
      LIST_ACTION,
      new Uint8Array(Buffer.from(makeKeyPem())),
      allowedPolicy(),
      SFTP_CONFIG,
    );

    expect(servingAtSpawn).toBe(true);
    expect(await agentSocketAccepts(sock)).toBe(false);
  });

  // POSIX file modes only: win32 has no 0600 (the per-user temp directory's ACL is the
  // control there), so the Windows legs skip and the Linux and macOS legs prove it.
  it.skipIf(process.platform === "win32")(
    "writes the batch file with mode 0600, captured at spawn time (Unix only)",
    async () => {
      let modeAtSpawn = 0;
      spawnMock.mockImplementation((_cmd, args) => {
        const batchPath = args[args.indexOf("-b") + 1] as string;
        modeAtSpawn = statSync(batchPath).mode & 0o777;
        return Promise.resolve(OK_RESULT);
      });

      await executeSftpAction(
        LIST_ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        allowedPolicy(),
        SFTP_CONFIG,
      );

      expect(modeAtSpawn).toBe(0o600);
    },
  );

  describe("golden batch file content per operation", () => {
    it("upload: put <local> <remote>, both double-quoted", async () => {
      let content = "";
      spawnMock.mockImplementation((_cmd, args) => {
        const batchPath = args[args.indexOf("-b") + 1] as string;
        content = readFileSync(batchPath, "utf8");
        return Promise.resolve(OK_RESULT);
      });

      await executeSftpAction(
        { ...UPLOAD_ACTION, local_path: listedFile },
        new Uint8Array(Buffer.from(makeKeyPem())),
        allowedPolicy({ local_dirs: [listedDir] }),
        SFTP_CONFIG,
      );

      expect(content).toBe(`put "${listedFile}" "/srv/report.pdf"\n`);
    });

    it("upload: the batch file names the resolved path, not the caller's spelling", async () => {
      let content = "";
      spawnMock.mockImplementation((_cmd, args) => {
        const batchPath = args[args.indexOf("-b") + 1] as string;
        content = readFileSync(batchPath, "utf8");
        return Promise.resolve(OK_RESULT);
      });

      await executeSftpAction(
        { ...UPLOAD_ACTION, local_path: `${listedDir}${sep}sub${sep}..${sep}report.pdf` },
        new Uint8Array(Buffer.from(makeKeyPem())),
        allowedPolicy({ local_dirs: [listedDir] }),
        SFTP_CONFIG,
      );

      expect(content).toBe(`put "${listedFile}" "/srv/report.pdf"\n`);
    });

    it("download: get <remote> <local>, both double-quoted", async () => {
      let content = "";
      spawnMock.mockImplementation((_cmd, args) => {
        const batchPath = args[args.indexOf("-b") + 1] as string;
        content = readFileSync(batchPath, "utf8");
        return Promise.resolve(OK_RESULT);
      });

      await executeSftpAction(
        { ...DOWNLOAD_ACTION, local_path: listedFile },
        new Uint8Array(Buffer.from(makeKeyPem())),
        allowedPolicy({ local_dirs: [listedDir] }),
        SFTP_CONFIG,
      );

      expect(content).toBe(`get "/srv/report.pdf" "${listedFile}"\n`);
    });

    it("list: ls -l <remote>, double-quoted", async () => {
      let content = "";
      spawnMock.mockImplementation((_cmd, args) => {
        const batchPath = args[args.indexOf("-b") + 1] as string;
        content = readFileSync(batchPath, "utf8");
        return Promise.resolve(OK_RESULT);
      });

      await executeSftpAction(
        LIST_ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        allowedPolicy(),
        SFTP_CONFIG,
      );

      expect(content).toBe('ls -l "/srv/reports"\n');
    });

    it("list: unchanged with an empty list of directories", async () => {
      let content = "";
      spawnMock.mockImplementation((_cmd, args) => {
        const batchPath = args[args.indexOf("-b") + 1] as string;
        content = readFileSync(batchPath, "utf8");
        return Promise.resolve(OK_RESULT);
      });

      await executeSftpAction(
        LIST_ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        allowedPolicy({ local_dirs: [] }),
        SFTP_CONFIG,
      );

      expect(spawnMock).toHaveBeenCalledOnce();
      expect(content).toBe('ls -l "/srv/reports"\n');
    });

    // Guard-flip pin (brief Step 4): dropping the quote-refusal in
    // `quotePath` makes this test red — the batch file would otherwise
    // carry an unescapable, desync-able quote inside a quoted token.
    it("refuses a double-quote inside a path before any temp file is written", async () => {
      await expect(
        executeSftpAction(
          { ...LIST_ACTION, remote_path: '/srv/"evil"' },
          new Uint8Array(Buffer.from(makeKeyPem())),
          allowedPolicy(),
          SFTP_CONFIG,
        ),
      ).rejects.toMatchObject({ code: ErrorCode.INVALID_INPUT });
      expect(spawnMock).not.toHaveBeenCalled();
    });

    // Review finding (Important 1): quoting alone does not neutralize a
    // leading '-'. OpenSSH sftp's batch reader (makeargv) strips the
    // surrounding quotes during tokenization, and only THEN does
    // parse_getput_flags/parse_ls_flags run getopt(3) over the result — so a
    // token that arrived as `"-r"` is an ordinary `-r` option by the time
    // sftp's own flag parser sees it, regardless of the quotes this injector
    // wrapped it in. One test per operation, on the field the option-flag
    // smuggling is reachable through for that operation; an upload's dash-led
    // local_path now meets the absolute-path refusal before the batch is built.
    it("upload: refuses a local_path starting with '-' (option-flag smuggling)", async () => {
      await expect(
        executeSftpAction(
          { ...UPLOAD_ACTION, local_path: "-r" },
          new Uint8Array(Buffer.from(makeKeyPem())),
          allowedPolicy(),
          SFTP_CONFIG,
        ),
      ).rejects.toMatchObject({ code: ErrorCode.INVALID_INPUT });
      expect(spawnMock).not.toHaveBeenCalled();
    });

    it("download: refuses a remote_path starting with '-' (option-flag smuggling)", async () => {
      await expect(
        executeSftpAction(
          { ...DOWNLOAD_ACTION, remote_path: "-r", local_path: listedFile },
          new Uint8Array(Buffer.from(makeKeyPem())),
          allowedPolicy({ local_dirs: [listedDir] }),
          SFTP_CONFIG,
        ),
      ).rejects.toMatchObject({ code: ErrorCode.INVALID_INPUT });
      expect(spawnMock).not.toHaveBeenCalled();
    });

    it("list: refuses a remote_path starting with '-' (option-flag smuggling)", async () => {
      await expect(
        executeSftpAction(
          { ...LIST_ACTION, remote_path: "-l" },
          new Uint8Array(Buffer.from(makeKeyPem())),
          allowedPolicy(),
          SFTP_CONFIG,
        ),
      ).rejects.toMatchObject({ code: ErrorCode.INVALID_INPUT });
      expect(spawnMock).not.toHaveBeenCalled();
    });

    // Review finding (Important 1), same tokenizer-desync family the quote
    // refusal exists to prevent: a trailing '\' immediately before the
    // closing '"' consumes that quote inside a double-quoted batch token,
    // merging this token with whatever follows and silently retargeting the
    // transfer.
    it("refuses a path ending in a trailing backslash", async () => {
      await expect(
        executeSftpAction(
          { ...LIST_ACTION, remote_path: "/srv/reports\\" },
          new Uint8Array(Buffer.from(makeKeyPem())),
          allowedPolicy(),
          SFTP_CONFIG,
        ),
      ).rejects.toMatchObject({ code: ErrorCode.INVALID_INPUT });
      expect(spawnMock).not.toHaveBeenCalled();
    });

    // Review finding (Important 1): core never re-validates a caller-supplied
    // action against the schema inside `useSecret` — this makes the
    // injector's own control-character/newline defense symmetric with the
    // quote and leading-dash checks rather than relying solely on the schema
    // boundary. A newline is the one character that could inject a second
    // scripted batch command.
    it("refuses a path containing a control character (e.g. newline — second-command injection)", async () => {
      await expect(
        executeSftpAction(
          { ...LIST_ACTION, remote_path: "/srv/reports\nput /etc/shadow x" },
          new Uint8Array(Buffer.from(makeKeyPem())),
          allowedPolicy(),
          SFTP_CONFIG,
        ),
      ).rejects.toMatchObject({ code: ErrorCode.INVALID_INPUT });
      expect(spawnMock).not.toHaveBeenCalled();
    });
  });

  describe("the local path is judged against local_dirs", () => {
    it.each(["upload", "download"] as const)(
      "%s: refuses a local_path outside the listed directories, nothing spawned",
      async (operation) => {
        await expectVaultError(
          () =>
            executeSftpAction(
              { ...ACTION[operation], local_path: outsideFile },
              new Uint8Array(Buffer.from(makeKeyPem())),
              allowedPolicy({ local_dirs: [listedDir] }),
              SFTP_CONFIG,
            ),
          ErrorCode.LOCAL_PATH_NOT_ALLOWED,
        );
        expect(spawnMock).not.toHaveBeenCalled();
      },
    );

    it("the host deny still comes before the local path", async () => {
      await expectVaultError(
        () =>
          executeSftpAction(
            { ...UPLOAD_ACTION, host: "other.example.com", local_path: outsideFile },
            new Uint8Array(Buffer.from(makeKeyPem())),
            allowedPolicy({ local_dirs: [listedDir] }),
            SFTP_CONFIG,
          ),
        ErrorCode.HOST_NOT_ALLOWED,
      );
      expect(spawnMock).not.toHaveBeenCalled();
    });
  });

  describe("a batch line is bounded by sftp's line buffer", () => {
    async function expectTooLong(action: SftpAction): Promise<void> {
      vi.mocked(mkdtempSync).mockClear();
      const err = await expectVaultError(
        () =>
          executeSftpAction(
            action,
            new Uint8Array(Buffer.from(makeKeyPem())),
            allowedPolicy({ local_dirs: [listedDir] }),
            SFTP_CONFIG,
          ),
        ErrorCode.INVALID_INPUT,
      );
      expect(err.message).toBe(TOO_LONG);
      expect(mkdtempSync).not.toHaveBeenCalled();
      expect(spawnMock).not.toHaveBeenCalled();
    }

    it.each(["upload", "download", "list"] as const)(
      "%s: refuses a batch line longer than sftp's line buffer, nothing spawned",
      async (operation) => {
        const remote = remoteForLineOf(operation, 2048);
        expect(Buffer.byteLength(batchLine(operation, remote))).toBe(2048);

        await expectTooLong(actionOn(operation, remote));
      },
    );

    it("download: a batch line of exactly 2047 bytes reaches the spawn", async () => {
      let content = "";
      spawnMock.mockImplementation((_cmd, args) => {
        const batchPath = args[args.indexOf("-b") + 1] as string;
        content = readFileSync(batchPath, "utf8");
        return Promise.resolve(OK_RESULT);
      });
      const remote = remoteForLineOf("download", 2047);

      await executeSftpAction(
        actionOn("download", remote),
        new Uint8Array(Buffer.from(makeKeyPem())),
        allowedPolicy({ local_dirs: [listedDir] }),
        SFTP_CONFIG,
      );

      expect(spawnMock).toHaveBeenCalledOnce();
      expect(content).toBe(batchLine("download", remote));
      expect(Buffer.byteLength(content)).toBe(2047);
    });

    it("download: the bound counts bytes, not characters", async () => {
      const remote = `/srv/${"ü".repeat(1100)}`;
      const line = batchLine("download", remote);
      expect(line.length).toBeLessThan(2047);
      expect(Buffer.byteLength(line)).toBeGreaterThan(2047);

      await expectTooLong(actionOn("download", remote));
    });
  });

  describe("a backslash or a glob character in the remote path", () => {
    async function refusedMessage(action: SftpAction): Promise<string> {
      vi.mocked(mkdtempSync).mockClear();
      const err = await expectVaultError(
        () =>
          executeSftpAction(
            action,
            new Uint8Array(Buffer.from(makeKeyPem())),
            allowedPolicy({ local_dirs: [listedDir] }),
            SFTP_CONFIG,
          ),
        ErrorCode.INVALID_INPUT,
      );
      expect(mkdtempSync).not.toHaveBeenCalled();
      expect(spawnMock).not.toHaveBeenCalled();
      return err.message;
    }

    async function batchContent(action: SftpAction): Promise<string> {
      let content = "";
      spawnMock.mockImplementation((_cmd, args) => {
        content = readFileSync(args[args.indexOf("-b") + 1] as string, "utf8");
        return Promise.resolve(OK_RESULT);
      });
      await executeSftpAction(
        action,
        new Uint8Array(Buffer.from(makeKeyPem())),
        allowedPolicy({ local_dirs: [listedDir] }),
        SFTP_CONFIG,
      );
      expect(spawnMock).toHaveBeenCalledOnce();
      return content;
    }

    it.each(
      TRANSFERS.flatMap((operation) => BACKSLASH_REMOTES.map((r) => [operation, r] as const)),
    )(
      "upload and download refuse a backslash in the remote path, before any temporary file: %s %s",
      async (operation, remote) => {
        expect(await refusedMessage(actionOn(operation, remote))).toBe(NO_BACKSLASH);
      },
    );

    it.each(["upload", "download", "list"] as const)(
      "a trailing backslash keeps its own message: %s",
      async (operation) => {
        expect(await refusedMessage(actionOn(operation, "/srv/reports\\"))).toBe(
          TRAILING_BACKSLASH,
        );
      },
    );

    it.each(["logs/*.txt", "a\\*"])(
      "list accepts a backslash and a pattern: %s reaches the batch file as sent",
      async (remote) => {
        expect(await batchContent(actionOn("list", remote))).toBe(batchLine("list", remote));
      },
    );

    it.each(TRANSFERS.flatMap((operation) => GLOB_REMOTES.map((r) => [operation, r] as const)))(
      "upload and download accept *, ? and [ in the remote path: %s %s",
      async (operation, remote) => {
        expect(await batchContent(actionOn(operation, remote))).toBe(batchLine(operation, remote));
      },
    );
  });

  it("reports sanitized when the spawn seam's redaction changed the captured output", async () => {
    spawnMock.mockResolvedValue({ ...OK_RESULT, redacted: true });

    const result = await executeSftpAction(
      LIST_ACTION,
      new Uint8Array(Buffer.from(makeKeyPem())),
      allowedPolicy(),
      SFTP_CONFIG,
    );

    expect(result.sanitized).toBe(true);
    // The flag rides the execution envelope only — the wire result is untouched.
    expect(result.result).not.toHaveProperty("sanitized");
  });

  it("carries the descendant sweep's outcome on the envelope, never the wire result", async () => {
    spawnMock.mockResolvedValue({
      ...OK_RESULT,
      exit_code: null,
      timed_out: true,
      signal: "SIGKILL",
      descendant_sweep: { killed: 0, failed: true },
    });

    const result = await executeSftpAction(
      LIST_ACTION,
      new Uint8Array(Buffer.from(makeKeyPem())),
      allowedPolicy(),
      SFTP_CONFIG,
    );

    expect(result.descendantSweep).toEqual({ killed: 0, failed: true });
    expect(result.result).not.toHaveProperty("descendant_sweep");
  });

  it("carries the spawn tier on the envelope as treeKill (2026-09-10)", async () => {
    spawnMock.mockResolvedValue({ ...OK_RESULT, tree_kill: "job" });

    const result = await executeSftpAction(
      LIST_ACTION,
      new Uint8Array(Buffer.from(makeKeyPem())),
      allowedPolicy(),
      SFTP_CONFIG,
    );

    expect(result.treeKill).toBe("job");
    // The tier rides the execution envelope only — the wire result is untouched.
    expect(result.result).not.toHaveProperty("tree_kill");
  });

  it("leaves treeKill off the envelope when the result carries none (POSIX)", async () => {
    spawnMock.mockResolvedValue(OK_RESULT);

    const result = await executeSftpAction(
      LIST_ACTION,
      new Uint8Array(Buffer.from(makeKeyPem())),
      allowedPolicy(),
      SFTP_CONFIG,
    );

    expect("treeKill" in result).toBe(false);
  });

  it("threads the policy's strict tree exit into the seam and onto the envelope (D2, 2026-09-10)", async () => {
    spawnMock.mockResolvedValue({ ...OK_RESULT, strict_tree_exit: true });

    const result = await executeSftpAction(
      LIST_ACTION,
      new Uint8Array(Buffer.from(makeKeyPem())),
      allowedPolicy({ strict_tree_exit: true }),
      SFTP_CONFIG,
    );

    expect(spawnMock.mock.calls[0]?.[2]).toMatchObject({ strictTreeExit: true });
    expect(result.strictTreeExit).toBe(true);
    // The flag rides the execution envelope only — the wire result is untouched.
    expect(result.result).not.toHaveProperty("strict_tree_exit");
  });

  it("leaves strictTreeExit off the envelope when the result carries none", async () => {
    spawnMock.mockResolvedValue(OK_RESULT);

    const result = await executeSftpAction(
      LIST_ACTION,
      new Uint8Array(Buffer.from(makeKeyPem())),
      allowedPolicy(),
      SFTP_CONFIG,
    );

    expect(spawnMock.mock.calls[0]?.[2]).not.toHaveProperty("strictTreeExit", true);
    expect("strictTreeExit" in result).toBe(false);
  });

  it("carries the isolation tiers the spawn ran under on the envelope, never the wire result (2026-10-14)", async () => {
    spawnMock.mockResolvedValue({
      ...OK_RESULT,
      isolation_mechanism: "unshare",
      fs_isolation_mechanism: "bwrap",
    });

    const result = await executeSftpAction(
      LIST_ACTION,
      new Uint8Array(Buffer.from(makeKeyPem())),
      allowedPolicy({ network_isolation: true, fs_isolation: true }),
      SFTP_CONFIG,
    );

    expect(result.isolationMechanism).toBe("unshare");
    expect(result.fsIsolationMechanism).toBe("bwrap");
    expect(result.result).not.toHaveProperty("isolation_mechanism");
    expect(result.result).not.toHaveProperty("fs_isolation_mechanism");
  });

  it("leaves both tiers off the envelope when the result carries none", async () => {
    spawnMock.mockResolvedValue(OK_RESULT);

    const result = await executeSftpAction(
      LIST_ACTION,
      new Uint8Array(Buffer.from(makeKeyPem())),
      allowedPolicy(),
      SFTP_CONFIG,
    );

    expect("isolationMechanism" in result).toBe(false);
    expect("fsIsolationMechanism" in result).toBe(false);
  });

  it("maps a non-zero exit to SFTP_OPERATION_FAILED", async () => {
    spawnMock.mockResolvedValue({ ...OK_RESULT, exit_code: 1, stderr: "No such file" });

    await expect(
      executeSftpAction(
        LIST_ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        allowedPolicy(),
        SFTP_CONFIG,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.SFTP_OPERATION_FAILED });
  });

  it("maps a plain exit 255 (connect/auth failure) to SSH_CONNECT_FAILED", async () => {
    spawnMock.mockResolvedValue({
      ...OK_RESULT,
      exit_code: 255,
      stderr: "ssh: connect to host 127.0.0.2 port 22: Connection refused",
    });

    await expect(
      executeSftpAction(
        LIST_ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        allowedPolicy(),
        SFTP_CONFIG,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.SSH_CONNECT_FAILED });
  });

  it("maps a spawn failure (spawn_failed) to SSH_CONNECT_FAILED", async () => {
    spawnMock.mockResolvedValue({ ...OK_RESULT, exit_code: null, spawn_failed: true });

    await expect(
      executeSftpAction(
        LIST_ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        allowedPolicy(),
        SFTP_CONFIG,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.SSH_CONNECT_FAILED });
  });

  it("returns PROCESS_TIMEOUT for a timed-out sftp run", async () => {
    spawnMock.mockResolvedValue({
      ...OK_RESULT,
      exit_code: null,
      timed_out: true,
      signal: "SIGKILL",
    });

    const result = await executeSftpAction(
      LIST_ACTION,
      new Uint8Array(Buffer.from(makeKeyPem())),
      allowedPolicy(),
      SFTP_CONFIG,
    );

    expect(result.result.timed_out).toBe(true);
    expect(result.result.error).toBe(ErrorCode.PROCESS_TIMEOUT);
    expect("descendantSweep" in result).toBe(false);
  });

  it("prefers PROCESS_TIMEOUT over the 255 connect classification (ssh-injector ordering)", async () => {
    // Seam-impossible input (a timed-out child reports exit_code null) — pins
    // the classification order only, mirroring ssh-injector's.
    spawnMock.mockResolvedValue({ ...OK_RESULT, exit_code: 255, timed_out: true });

    await expect(
      executeSftpAction(
        LIST_ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        allowedPolicy(),
        SFTP_CONFIG,
      ),
    ).resolves.toMatchObject({ result: { error: ErrorCode.PROCESS_TIMEOUT } });
  });

  it("maps host-key verification failure text to SSH_HOST_KEY_MISMATCH", async () => {
    spawnMock.mockResolvedValue({
      ...OK_RESULT,
      exit_code: 255,
      stderr: "Host key verification failed.",
    });

    await expect(
      executeSftpAction(
        LIST_ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        allowedPolicy(),
        SFTP_CONFIG,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.SSH_HOST_KEY_MISMATCH });
  });

  it("passes the isolation flags through to the spawn seam", async () => {
    await executeSftpAction(
      LIST_ACTION,
      new Uint8Array(Buffer.from(makeKeyPem())),
      allowedPolicy({ network_isolation: true, fs_isolation: true }),
      SFTP_CONFIG,
    );

    const [, , opts] = spawnMock.mock.calls[0] as [
      string,
      string[],
      { networkIsolation?: boolean; fsIsolation?: boolean },
    ];
    expect(opts.networkIsolation).toBe(true);
    expect(opts.fsIsolation).toBe(true);
  });

  it("defaults isolation flags to false when the policy leaves them unset", async () => {
    await executeSftpAction(
      LIST_ACTION,
      new Uint8Array(Buffer.from(makeKeyPem())),
      allowedPolicy(),
      SFTP_CONFIG,
    );

    const [, , opts] = spawnMock.mock.calls[0] as [
      string,
      string[],
      { networkIsolation?: boolean; fsIsolation?: boolean },
    ];
    expect(opts.networkIsolation).toBe(false);
    expect(opts.fsIsolation).toBe(false);
  });

  it("propagates a fail-closed isolation refusal from the spawn seam", async () => {
    spawnMock.mockRejectedValue(VaultError.networkIsolationUnavailable("mocked"));

    await expect(
      executeSftpAction(
        LIST_ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        allowedPolicy({ network_isolation: true }),
        SFTP_CONFIG,
      ),
    ).rejects.toMatchObject({ code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE });
  });
});

describe.runIf(process.platform === "win32")(
  "executeSftpAction refuses an MSYS/Cygwin sftp client (D58)",
  () => {
    const spawnMock = vi.mocked(spawnCaptured);
    let fixtureDir: string;
    let stub: string;
    const savedPath = process.env.PATH;

    beforeEach(() => {
      spawnMock.mockReset();
      spawnMock.mockResolvedValue(OK_RESULT);
      fixtureDir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-msys-sftp-")));
      stub = join(fixtureDir, "sftp.exe");
      writeFileSync(stub, "");
      writeFileSync(join(fixtureDir, "msys-2.0.dll"), "");
      process.env.PATH = fixtureDir;
    });

    afterEach(() => {
      process.env.PATH = savedPath;
      rmSync(fixtureDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    it("refuses before any spawn", async () => {
      await expect(
        executeSftpAction(
          LIST_ACTION,
          new Uint8Array(Buffer.from(makeKeyPem())),
          policy({
            host_allowlist: ["deploy.example.com"],
            command_allowlist: [stub],
          }),
          SFTP_CONFIG,
        ),
      ).rejects.toMatchObject({ code: ErrorCode.SSH_CLIENT_UNSUPPORTED });
      expect(spawnMock).not.toHaveBeenCalled();
    });

    it("guard-flip: without the DLL the same stub is spawned", async () => {
      rmSync(join(fixtureDir, "msys-2.0.dll"));
      await executeSftpAction(
        LIST_ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        policy({
          host_allowlist: ["deploy.example.com"],
          command_allowlist: [stub],
        }),
        SFTP_CONFIG,
      );
      expect(spawnMock).toHaveBeenCalledOnce();
      const [command] = spawnMock.mock.calls[0] as [string, string[], unknown];
      expect(command.toLowerCase()).toBe(stub.toLowerCase());
    });
  },
);
