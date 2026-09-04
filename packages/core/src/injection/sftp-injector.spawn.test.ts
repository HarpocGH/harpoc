import { generateKeyPairSync } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionConfig, InjectionPolicy, SftpAction } from "@harpoc/shared";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { executeSftpAction } from "./sftp-injector.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
import { system32Path } from "../win32-paths.js";

vi.mock("./spawn-captured.js", () => ({ spawnCaptured: vi.fn() }));

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

const SFTP = resolveExecutable("sftp", controlledPathDirs());
const describeSftp = SFTP ? describe : describe.skip;

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
    ...overrides,
  };
}

const SFTP_CONFIG: ConnectionConfig = {
  ssh: { known_hosts: ["deploy.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] },
};

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
  local_path: "/tmp/report.pdf",
};

const DOWNLOAD_ACTION: SftpAction = {
  type: "sftp",
  host: "deploy.example.com",
  user: "deploy",
  operation: "download",
  remote_path: "/srv/report.pdf",
  local_path: "/tmp/report.pdf",
};

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
    expect(args.slice(-4)).toEqual([
      "-oBatchMode=yes",
      "-b",
      batchFile,
      "deploy@deploy.example.com",
    ]);

    expect(opts.env.SSH_AUTH_SOCK).toBeTruthy();
    expect(args.every((a) => !a.includes("PRIVATE KEY"))).toBe(true);
    expect(opts.redact).toContain(keyPem);
  });

  it("passes a non-22 port as -P ahead of the batch-mode flags", async () => {
    await executeSftpAction(
      { ...LIST_ACTION, port: 2222 },
      new Uint8Array(Buffer.from(makeKeyPem())),
      allowedPolicy(),
      SFTP_CONFIG,
    );
    const [, args] = spawnMock.mock.calls[0] as [string, string[], { env: Record<string, string> }];
    const tail = args.slice(-6);
    expect(tail).toEqual([
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

  it("writes the batch file with mode 0600, captured at spawn time (Unix only)", async () => {
    if (process.platform === "win32") return;
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
  });

  describe("golden batch file content per operation", () => {
    it("upload: put <local> <remote>, both double-quoted", async () => {
      let content = "";
      spawnMock.mockImplementation((_cmd, args) => {
        const batchPath = args[args.indexOf("-b") + 1] as string;
        content = readFileSync(batchPath, "utf8");
        return Promise.resolve(OK_RESULT);
      });

      await executeSftpAction(
        UPLOAD_ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        allowedPolicy(),
        SFTP_CONFIG,
      );

      expect(content).toBe('put "/tmp/report.pdf" "/srv/report.pdf"\n');
    });

    it("download: get <remote> <local>, both double-quoted", async () => {
      let content = "";
      spawnMock.mockImplementation((_cmd, args) => {
        const batchPath = args[args.indexOf("-b") + 1] as string;
        content = readFileSync(batchPath, "utf8");
        return Promise.resolve(OK_RESULT);
      });

      await executeSftpAction(
        DOWNLOAD_ACTION,
        new Uint8Array(Buffer.from(makeKeyPem())),
        allowedPolicy(),
        SFTP_CONFIG,
      );

      expect(content).toBe('get "/srv/report.pdf" "/tmp/report.pdf"\n');
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
    // smuggling is reachable through for that operation.
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
          { ...DOWNLOAD_ACTION, remote_path: "-r" },
          new Uint8Array(Buffer.from(makeKeyPem())),
          allowedPolicy(),
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
      rmSync(fixtureDir, { recursive: true, force: true });
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
