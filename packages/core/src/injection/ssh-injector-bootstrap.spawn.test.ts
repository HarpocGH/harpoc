import { randomBytes } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { InjectionPolicy } from "@harpoc/shared";
import {
  ErrorCode,
  SSH_BOOTSTRAP_CONNECT_TIMEOUT_SEC,
  SSH_HOST_KEY_TYPES,
  SSH_INSTALL_KEY_TYPES,
  VaultError,
} from "@harpoc/shared";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";
import { serialized } from "./__fixtures__/serialized.js";
import { HOST_KEY, KEY_A, KEY_B } from "./__fixtures__/ssh-public-keys.js";
import { redactCaptured, spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedOptions, SpawnCapturedResult } from "./spawn-captured.js";
import { sshPasswordLoginArgs } from "./ssh-common.js";
import { parseSshPublicKey } from "./ssh-common-keys.js";
import type { SshPublicKey } from "./ssh-common-keys.js";
import {
  type BootstrapCall,
  type BootstrapOutcome,
  refuseWindowsVaultHost,
  runBootstrap,
} from "./ssh-injector-bootstrap.js";
import { bootstrapStdin } from "./ssh-injector-bootstrap-script.js";

vi.mock("./spawn-captured.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./spawn-captured.js")>();
  return { ...actual, spawnCaptured: vi.fn(), redactCaptured: vi.fn(actual.redactCaptured) };
});
vi.mock("./ssh-injector-bootstrap-script.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./ssh-injector-bootstrap-script.js")>();
  return {
    ...actual,
    BOOTSTRAP_REMOTE_COMMAND: "REMOTE",
    bootstrapStdin: vi.fn((frame: string, keyLine: string, password?: Buffer) =>
      Buffer.from([frame, keyLine, password?.toString() ?? ""].join("\n")),
    ),
  };
});
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    mkdtempSync: vi.fn(actual.mkdtempSync),
    rmSync: vi.fn(actual.rmSync),
    writeFileSync: vi.fn(actual.writeFileSync),
  };
});

const {
  mkdtempSync: realMkdtempSync,
  rmSync: realRmSync,
  writeFileSync: realWriteFileSync,
} = await vi.importActual<typeof import("node:fs")>("node:fs");
const { redactCaptured: realRedactCaptured } =
  await vi.importActual<typeof import("./spawn-captured.js")>("./spawn-captured.js");

const win32 = process.platform === "win32";
const LAUNCHER = win32 ? "askpass.cmd" : "askpass.sh";
const NAMES_REFUSED = "host and user must be names of letters, digits, '.', '_' and '-'";
const MARKS_UNDRAWN = "ssh bootstrap could not draw its marks";
const TEMP_FILE_UNPREPARED = "a temporary file of the ssh bootstrap could not be prepared";
const MARK = /^[A-Za-z0-9_-]{24}$/;
const MARK_LINE = /\n([A-Za-z0-9_-]{24})\n/;
const MARKER = "HARPOC-T10-STREAM-MARKER";

const PASSWORD_A = "a";
const PASSWORD_METHOD = "password";
const PASSWORD_USER = "deploy";
const PASSWORD_E = "e";

const HOST_KEYS: SshPublicKey[] = [HOST_KEY, KEY_B].map(
  (line) => parseSshPublicKey(line, SSH_HOST_KEY_TYPES) as SshPublicKey,
);
const INSTALL_KEY = parseSshPublicKey(KEY_A, SSH_INSTALL_KEY_TYPES) as SshPublicKey;

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
    ssh_bootstrap: null,
    ...overrides,
  };
}

function freshPassword(): Buffer {
  return Buffer.from(randomBytes(18).toString("base64url"));
}

function bootstrapCall(overrides: Partial<BootstrapCall> = {}): BootstrapCall {
  return {
    sshPath: "/usr/bin/ssh",
    host: "host.example",
    port: 2222,
    user: "deploy",
    hostKeys: HOST_KEYS,
    installKey: INSTALL_KEY,
    sudoers: false,
    password: freshPassword(),
    policy: policy(),
    budgetMs: 120_000,
    ...overrides,
  };
}

const BASE_RESULT: SpawnCapturedResult = {
  exit_code: 255,
  stdout: "",
  stderr: "",
  timed_out: false,
  truncated: false,
  signal: null,
  spawn_failed: false,
  redacted: false,
};

interface AtSpawn {
  command: string;
  argv: string[];
  opts: SpawnCapturedOptions;
  env: Record<string, string>;
  redact: string[];
  word: string;
  frame: string;
  knownHostsFile: string;
  globalFile: string;
  knownHosts: string;
  globalKnownHosts: string;
  launcherText: string;
}

function optionPath(argv: string[], name: string): string {
  const word = argv.find((a) => a.startsWith(`${name}="`)) ?? "";
  return word.slice(name.length + 2, -1);
}

function scriptSeam(
  answer: (at: AtSpawn) => SpawnCapturedResult | Promise<SpawnCapturedResult>,
): AtSpawn[] {
  const spawns: AtSpawn[] = [];
  vi.mocked(spawnCaptured).mockImplementation(async (command, argv, opts) => {
    const knownHostsFile = optionPath(argv, "UserKnownHostsFile");
    const globalFile = optionPath(argv, "GlobalKnownHostsFile");
    const at: AtSpawn = {
      command,
      argv: [...argv],
      opts,
      env: { ...opts.env },
      redact: [...(opts.redact ?? [])],
      word: opts.env.HARPOC_SSH_WORD as string,
      frame: vi.mocked(bootstrapStdin).mock.calls.at(-1)?.[0] as string,
      knownHostsFile,
      globalFile,
      knownHosts: readFileSync(knownHostsFile, "utf8"),
      globalKnownHosts: readFileSync(globalFile, "utf8"),
      launcherText: readFileSync(opts.env.SSH_ASKPASS as string, "utf8"),
    };
    spawns.push(at);
    return answer(at);
  });
  return spawns;
}

function seamResult(at: AtSpawn, raw: Partial<SpawnCapturedResult>): SpawnCapturedResult {
  const stdout = realRedactCaptured(raw.stdout ?? "", at.redact);
  const stderr = realRedactCaptured(raw.stderr ?? "", at.redact);
  return {
    ...BASE_RESULT,
    ...raw,
    stdout,
    stderr,
    redacted: stdout !== (raw.stdout ?? "") || stderr !== (raw.stderr ?? ""),
  };
}

function overrideTempEnv(dir: string): { TMPDIR?: string; TMP?: string; TEMP?: string } {
  const saved = { TMPDIR: process.env.TMPDIR, TMP: process.env.TMP, TEMP: process.env.TEMP };
  process.env.TMPDIR = dir;
  process.env.TMP = dir;
  process.env.TEMP = dir;
  return saved;
}

function restoreTempEnv(saved: { TMPDIR?: string; TMP?: string; TEMP?: string }): void {
  if (saved.TMPDIR === undefined) delete process.env.TMPDIR;
  else process.env.TMPDIR = saved.TMPDIR;
  if (saved.TMP === undefined) delete process.env.TMP;
  else process.env.TMP = saved.TMP;
  if (saved.TEMP === undefined) delete process.env.TEMP;
  else process.env.TEMP = saved.TEMP;
}

function refusedError(outcome: BootstrapOutcome, kind: "not_spawned" | "refused"): VaultError {
  expect(outcome.kind).toBe(kind);
  return (outcome as { error: VaultError }).error;
}

let tempRoot: string;
let saved: { TMPDIR?: string; TMP?: string; TEMP?: string };

beforeEach(() => {
  tempRoot = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-bootstrap-t-")));
  saved = overrideTempEnv(tempRoot);
  vi.mocked(spawnCaptured).mockReset();
  vi.mocked(bootstrapStdin).mockClear();
});

afterEach(() => {
  restoreTempEnv(saved);
  vi.mocked(redactCaptured).mockReset();
  vi.mocked(writeFileSync).mockReset();
  vi.mocked(mkdtempSync).mockReset();
  vi.mocked(rmSync).mockReset();
  rmSync(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("runBootstrap", () => {
  it("the argv", async () => {
    const spawns = scriptSeam(() => BASE_RESULT);
    await runBootstrap(bootstrapCall());
    await runBootstrap(bootstrapCall({ port: 22 }));
    const [first, second] = spawns as [AtSpawn, AtSpawn];
    expect(first.command).toBe("/usr/bin/ssh");
    expect(first.argv.length).toBe(59);
    expect(basename(first.knownHostsFile)).toBe("known_hosts");
    expect(basename(first.globalFile)).toBe("global_known_hosts");
    expect(first.argv.slice(0, 52)).toEqual(
      sshPasswordLoginArgs(
        { file: first.knownHostsFile, globalFile: first.globalFile },
        SSH_BOOTSTRAP_CONNECT_TIMEOUT_SEC,
      ),
    );
    expect(first.argv.slice(52)).toEqual([
      "-p",
      "2222",
      "-l",
      "deploy",
      "--",
      "host.example",
      "REMOTE",
    ]);
    expect(second.argv.length).toBe(59);
    expect(second.argv.slice(52)).toEqual([
      "-p",
      "22",
      "-l",
      "deploy",
      "--",
      "host.example",
      "REMOTE",
    ]);
  });

  it("the host is lower-cased once, for all three", async () => {
    const spawns = scriptSeam(() => BASE_RESULT);
    await runBootstrap(bootstrapCall({ host: "Host.Example" }));
    const [at] = spawns as [AtSpawn];
    expect(at.argv.at(-2)).toBe("host.example");
    expect(at.knownHosts).toBe(`[host.example]:2222 ${HOST_KEY}\n[host.example]:2222 ${KEY_B}\n`);
    expect(at.env.HARPOC_SSH_PROMPT).toBe("deploy@host.example's password: ");
  });

  it("the known-hosts file holds the block's keys and the global one is empty", async () => {
    const spawns = scriptSeam(() => BASE_RESULT);
    await runBootstrap(bootstrapCall({ port: 22 }));
    await runBootstrap(bootstrapCall({ hostKeys: HOST_KEYS.slice(0, 1) }));
    const [bare, bracketed] = spawns as [AtSpawn, AtSpawn];
    expect(bare.knownHosts).toBe(`host.example ${HOST_KEY}\nhost.example ${KEY_B}\n`);
    expect(bare.globalKnownHosts).toBe("");
    expect(dirname(bare.globalFile)).toBe(dirname(bare.knownHostsFile));
    expect(bracketed.knownHosts).toBe(`[host.example]:2222 ${HOST_KEY}\n`);
    expect(bracketed.globalKnownHosts).toBe("");
  });

  it("the environment", async () => {
    const spawns = scriptSeam(() => BASE_RESULT);
    const call = bootstrapCall();
    const password = call.password.toString();
    await runBootstrap(call);
    await runBootstrap(bootstrapCall());
    const [first, second] = spawns as [AtSpawn, AtSpawn];
    expect(Object.keys(first.env).sort()).toEqual(
      [
        "PATH",
        ...(win32 ? ["SystemRoot", "ProgramData"] : []),
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
        "HARPOC_SSH_PROMPT",
        "HARPOC_SSH_WORD",
        "HARPOC_SSH_PASSWORD",
      ].sort(),
    );
    expect(first.env.HARPOC_SSH_PASSWORD === password).toBe(true);
    expect(first.env.SSH_ASKPASS_REQUIRE).toBe("force");
    const launcher = first.env.SSH_ASKPASS as string;
    expect(basename(launcher)).toBe(LAUNCHER);
    expect(basename(dirname(launcher)).startsWith("harpoc-ssh-askpass-")).toBe(true);
    expect(dirname(dirname(launcher))).toBe(tempRoot);
    expect(first.launcherText.endsWith(win32 ? " %* <NUL\r\n" : ' "$@" </dev/null\n')).toBe(true);
    expect(first.env.HARPOC_SSH_PROMPT).toBe("deploy@host.example's password: ");
    expect(MARK.test(first.word)).toBe(true);
    expect(MARK.test(second.word)).toBe(true);
    expect(first.word === second.word).toBe(false);
  });

  it("the input", async () => {
    const spawns = scriptSeam(() => BASE_RESULT);
    const plain = bootstrapCall();
    const withFlag = bootstrapCall({ sudoers: true });
    await runBootstrap(plain);
    await runBootstrap(withFlag);
    const calls = vi.mocked(bootstrapStdin).mock.calls;
    expect(calls.length).toBe(2);
    const [plainCall, flagCall] = calls as [
      [string, string, Buffer | undefined],
      [string, string, Buffer | undefined],
    ];
    expect(MARK.test(plainCall[0])).toBe(true);
    expect(plainCall[1]).toBe(KEY_A);
    expect(plainCall[2] === undefined).toBe(true);
    expect(MARK.test(flagCall[0])).toBe(true);
    expect(flagCall[1]).toBe(KEY_A);
    expect(flagCall[2] === withFlag.password).toBe(true);
    const results = vi.mocked(bootstrapStdin).mock.results;
    for (const [index, call] of [plain, withFlag].entries()) {
      const at = spawns[index] as AtSpawn;
      expect(at.opts.stdin === results[index]?.value).toBe(true);
      expect(at.frame === at.word).toBe(false);
      expect(at.redact.length).toBe(1);
      expect(at.redact[0] === call.password.toString()).toBe(true);
    }
  });

  it("the policy's isolation and strict-tree flags reach the seam", async () => {
    const spawns = scriptSeam(() => BASE_RESULT);
    await runBootstrap(bootstrapCall());
    await runBootstrap(
      bootstrapCall({
        policy: policy({ network_isolation: true, fs_isolation: true, strict_tree_exit: true }),
        budgetMs: 4_321,
      }),
    );
    const [off, on] = spawns as [AtSpawn, AtSpawn];
    expect([off.opts.networkIsolation, off.opts.fsIsolation, off.opts.strictTreeExit]).toEqual([
      false,
      false,
      false,
    ]);
    expect([on.opts.networkIsolation, on.opts.fsIsolation, on.opts.strictTreeExit]).toEqual([
      true,
      true,
      true,
    ]);
    expect(off.opts.timeoutMs).toBe(120_000);
    expect(on.opts.timeoutMs).toBe(4_321);
  });

  it.each([
    ["a result", () => BASE_RESULT, "fulfilled"],
    [
      "a seam that rejects with a VaultError",
      () => Promise.reject(VaultError.fsIsolationUnavailable("not on this host")),
      "fulfilled",
    ],
    [
      "a seam that rejects with an Error",
      () => Promise.reject(new Error("seam broke")),
      "rejected",
    ],
  ] as const)(
    "nothing the seam was handed holds the password once the call settled: %s",
    async (_name, answer, settles) => {
      const spawns = scriptSeam(answer);
      const [settled] = await Promise.allSettled([runBootstrap(bootstrapCall({ sudoers: true }))]);
      expect(settled.status).toBe(settles);
      const [at] = spawns as [AtSpawn];
      expect("HARPOC_SSH_PASSWORD" in at.opts.env).toBe(false);
      expect(at.opts.redact?.length).toBe(0);
    },
  );

  it("the marks hold no form of the password", async () => {
    const spawns = scriptSeam(() => BASE_RESULT);
    for (let i = 0; i < 50; i++) {
      await runBootstrap(bootstrapCall({ password: Buffer.from(PASSWORD_A) }));
    }
    const marks = spawns.flatMap((at) => [at.word, at.frame]);
    expect(marks.length).toBe(100);
    for (const mark of marks) {
      expect(MARK.test(mark)).toBe(true);
      for (const form of ["a", "A", "YQ", "61"]) expect(mark.includes(form)).toBe(false);
      expect(realRedactCaptured(`\n${mark}\n`, [PASSWORD_A])).toBe(`\n${mark}\n`);
      expect(realRedactCaptured(`\\\n${mark}\n`, [PASSWORD_A])).toBe(`\\\n${mark}\n`);
    }
  });

  it("a mark that only the redaction inside a text with a backslash changes is drawn again", async () => {
    const altered = new Set<string>();
    vi.mocked(redactCaptured).mockImplementation((text, secrets) => {
      const mark = MARK_LINE.exec(text)?.[1];
      if (text.startsWith("\\") && mark !== undefined && (altered.has(mark) || altered.size < 3)) {
        altered.add(mark);
        return text.replace(mark, "[REDACTED]");
      }
      return realRedactCaptured(text, secrets);
    });
    const spawns = scriptSeam(() => BASE_RESULT);
    await runBootstrap(bootstrapCall());
    const [at] = spawns as [AtSpawn];
    expect(altered.size).toBe(3);
    expect(altered.has(at.word)).toBe(false);
    expect(altered.has(at.frame)).toBe(false);
  });

  it("a redaction that changes every mark inside such a text draws none", async () => {
    vi.mocked(redactCaptured).mockImplementation((text, secrets) => {
      const mark = MARK_LINE.exec(text)?.[1];
      if (text.startsWith("\\") && mark !== undefined) return text.replace(mark, "[REDACTED]");
      return realRedactCaptured(text, secrets);
    });
    const outcome = await runBootstrap(bootstrapCall());
    const error = refusedError(outcome, "not_spawned");
    expect(error.code).toBe(ErrorCode.INTERNAL_ERROR);
    expect(error.message).toBe(MARKS_UNDRAWN);
    expect("spawn" in outcome).toBe(false);
    expect(vi.mocked(spawnCaptured)).not.toHaveBeenCalled();
    expect(readdirSync(tempRoot)).toEqual([]);
  });

  describe("the helper's files and the known-hosts files are gone afterwards", () => {
    function directoriesAtSpawn(at: AtSpawn): string[] {
      return [dirname(at.knownHostsFile), dirname(at.env.SSH_ASKPASS as string)];
    }

    it("on a result", async () => {
      const spawns = scriptSeam(() => BASE_RESULT);
      await runBootstrap(bootstrapCall());
      const [at] = spawns as [AtSpawn];
      for (const dir of directoriesAtSpawn(at)) expect(existsSync(dir)).toBe(false);
      expect(readdirSync(tempRoot)).toEqual([]);
    });

    it("on a seam that rejects with a VaultError", async () => {
      const err = VaultError.fsIsolationUnavailable("not on this host");
      const spawns = scriptSeam(() => Promise.reject(err));
      const outcome = await runBootstrap(bootstrapCall());
      expect(refusedError(outcome, "not_spawned")).toBe(err);
      const [at] = spawns as [AtSpawn];
      for (const dir of directoriesAtSpawn(at)) expect(existsSync(dir)).toBe(false);
      expect(readdirSync(tempRoot)).toEqual([]);
    });

    it("on a seam that rejects with an Error, which leaves", async () => {
      const boom = new Error("seam broke");
      const spawns = scriptSeam(() => Promise.reject(boom));
      let thrown: unknown;
      try {
        await runBootstrap(bootstrapCall());
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBe(boom);
      const [at] = spawns as [AtSpawn];
      for (const dir of directoriesAtSpawn(at)) expect(existsSync(dir)).toBe(false);
      expect(readdirSync(tempRoot)).toEqual([]);
    });
  });

  it.each([
    [
      "network",
      { network_isolation: true, fs_isolation: false },
      () => VaultError.networkIsolationUnavailable("none"),
    ],
    [
      "filesystem",
      { network_isolation: false, fs_isolation: true },
      () => VaultError.fsIsolationUnavailable("none"),
    ],
  ] as const)(
    "%s isolation that cannot be delivered is not_spawned with the seam's code and the policy's two flags",
    async (_name, flags, make) => {
      const err = make();
      vi.mocked(spawnCaptured).mockRejectedValue(err);
      const outcome = await runBootstrap(bootstrapCall({ policy: policy(flags) }));
      expect(Object.keys(outcome).sort()).toEqual(["error", "kind", "spawn"]);
      expect(refusedError(outcome, "not_spawned")).toBe(err);
      expect(outcome.spawn).toStrictEqual({ ...flags });
    },
  );

  it.each([
    ["a host with a leading dash", { host: "-oProxyCommand=x" }],
    ["a host with a blank", { host: "host example" }],
    ["an empty host", { host: "" }],
    ["a user with a leading dash", { user: "-l" }],
    ["a user with an at sign", { user: "deploy@host" }],
    ["a port of 0", { port: 0 }],
    ["a port of 65536", { port: 65_536 }],
    ["a port that is no integer", { port: 22.5 }],
    ["a port that is no number", { port: Number.NaN }],
  ] as const)("%s is not_spawned with INVALID_SSH_CONFIG", async (_name, overrides) => {
    const outcome = await runBootstrap(bootstrapCall(overrides));
    const error = refusedError(outcome, "not_spawned");
    expect(error.code).toBe(ErrorCode.INVALID_SSH_CONFIG);
    expect(error.message).toBe(NAMES_REFUSED);
    expect("spawn" in outcome).toBe(false);
    expect(vi.mocked(spawnCaptured)).not.toHaveBeenCalled();
    expect(readdirSync(tempRoot)).toEqual([]);
  });

  it("a port of 1 and of 65535 pass", async () => {
    scriptSeam(() => BASE_RESULT);
    await runBootstrap(bootstrapCall({ port: 1 }));
    await runBootstrap(bootstrapCall({ port: 65_535 }));
    expect(vi.mocked(spawnCaptured).mock.calls.length).toBe(2);
  });

  describe("a temporary file that cannot be written", () => {
    function ioError(code: string): NodeJS.ErrnoException {
      const err = new Error(`${code}: injected`) as NodeJS.ErrnoException;
      err.code = code;
      return err;
    }

    function failMkdtemp(prefix: string): void {
      vi.mocked(mkdtempSync).mockImplementation((path, options) => {
        if (basename(String(path)) === prefix) throw ioError("EACCES");
        return realMkdtempSync(path, options);
      });
    }

    function failWrite(name: string): void {
      vi.mocked(writeFileSync).mockImplementation((file, data, options) => {
        if (basename(String(file)) === name) throw ioError("ENOSPC");
        realWriteFileSync(file, data, options);
      });
    }

    async function expectUnprepared(): Promise<void> {
      const outcome = await runBootstrap(bootstrapCall());
      const error = refusedError(outcome, "not_spawned");
      expect(error.code).toBe(ErrorCode.FILE_IO_ERROR);
      expect(error.message).toBe(TEMP_FILE_UNPREPARED);
      expect("spawn" in outcome).toBe(false);
      expect(vi.mocked(spawnCaptured)).not.toHaveBeenCalled();
    }

    it.each([
      ["the known-hosts directory", () => failMkdtemp("harpoc-ssh-")],
      ["the known-hosts file", () => failWrite("known_hosts")],
      ["the global known-hosts file", () => failWrite("global_known_hosts")],
      ["the helper's directory", () => failMkdtemp("harpoc-ssh-askpass-")],
      ["the helper's script", () => failWrite("askpass.mjs")],
      ["the helper's launcher", () => failWrite(LAUNCHER)],
    ] as const)("%s: not_spawned with FILE_IO_ERROR, nothing left", async (_name, arm) => {
      arm();
      await expectUnprepared();
      expect(readdirSync(tempRoot)).toEqual([]);
    });

    it("a removal that fails after the helper's failed write is FILE_IO_ERROR as well", async () => {
      failWrite("askpass.mjs");
      vi.mocked(rmSync).mockImplementation((path, options) => {
        if (basename(String(path)).startsWith("harpoc-ssh-askpass-")) {
          throw ioError("EBUSY");
        }
        realRmSync(path, options);
      });
      await expectUnprepared();
      const left = readdirSync(tempRoot);
      expect(left.length).toBe(1);
      expect((left[0] as string).startsWith("harpoc-ssh-askpass-")).toBe(true);
    });
  });

  it("the spawn fields", async () => {
    scriptSeam(() => ({
      ...BASE_RESULT,
      exit_code: null,
      timed_out: true,
      truncated: true,
      redacted: true,
      signal: "SIGKILL",
      isolation_mechanism: "bwrap",
      fs_isolation_mechanism: "landlock",
      descendant_sweep: { killed: 1, failed: false },
      tree_kill: "job",
      strict_tree_exit: true,
    }));
    const full = await runBootstrap(
      bootstrapCall({
        policy: policy({ network_isolation: true, fs_isolation: true, strict_tree_exit: true }),
      }),
    );
    expect(full.spawn).toStrictEqual({
      exit_code: null,
      timed_out: true,
      truncated: true,
      network_isolation: true,
      isolation_mechanism: "bwrap",
      fs_isolation: true,
      fs_isolation_mechanism: "landlock",
      sanitized: true,
      descendant_sweep: { killed: 1, failed: false },
      tree_kill: "job",
      strict_tree_exit: true,
    });
    scriptSeam(() => ({ ...BASE_RESULT, exit_code: 3 }));
    const bare = await runBootstrap(bootstrapCall());
    expect(bare.spawn).toStrictEqual({
      exit_code: 3,
      timed_out: false,
      network_isolation: false,
      fs_isolation: false,
    });
  });

  it.each([
    [
      "a status",
      "done",
      (at: AtSpawn) => ({
        exit_code: 0,
        stdout: `${MARKER}\n\nharpoc-bootstrap-v1 ${at.frame} not_asked installed\n`,
        stderr: `${MARKER}\n${at.word}\n${MARKER}`,
      }),
    ],
    [
      "a failed step",
      "refused",
      (at: AtSpawn) => ({
        exit_code: 0,
        stdout: `${MARKER}\n\nharpoc-bootstrap-v1 ${at.frame} not_asked failed\n`,
        stderr: `\n${at.word}\n${MARKER}`,
      }),
    ],
    [
      "a session without a status",
      "unconfirmed",
      (at: AtSpawn) => ({ exit_code: 0, stdout: MARKER, stderr: `\n${at.word}\n${MARKER}` }),
    ],
    ["no connection", "refused", () => ({ exit_code: 255, stdout: "", stderr: `${MARKER}\n` })],
    [
      "a client that did not start",
      "not_spawned",
      () => ({ spawn_failed: true, stdout: MARKER, stderr: MARKER }),
    ],
  ] as const)("nothing of the streams is returned: %s", async (_name, kind, streams) => {
    scriptSeam((at) => seamResult(at, streams(at)));
    const outcome = await runBootstrap(bootstrapCall());
    expect(outcome.kind).toBe(kind);
    expectAbsent(serialized(outcome), MARKER, "the outcome, its error's message included");
  });

  it.each([
    ["the user's name", PASSWORD_USER],
    ["the method's name", PASSWORD_METHOD],
  ])(
    "the reader reads with the lower-cased host and the seam's own redaction: a password that is %s",
    async (_name, secret) => {
      scriptSeam((at) =>
        seamResult(at, {
          exit_code: 255,
          stderr: "deploy@host.example: Permission denied (publickey,password).\r\n",
        }),
      );
      const outcome = await runBootstrap(
        bootstrapCall({ host: "Host.Example", password: Buffer.from(secret) }),
      );
      expect(refusedError(outcome, "refused").code).toBe(ErrorCode.SSH_PASSWORD_REFUSED);
    },
  );

  it("the reader reads with the call's word and frame: a password that is a letter of the status", async () => {
    scriptSeam((at) =>
      seamResult(at, {
        exit_code: 0,
        stdout: `\nharpoc-bootstrap-v1 ${at.frame} not_asked installed\n`,
        stderr: `\n${at.word}\n`,
      }),
    );
    const outcome = await runBootstrap(bootstrapCall({ password: Buffer.from(PASSWORD_E) }));
    expect(outcome.kind).toBe("done");
    expect(outcome).toMatchObject({ key: "installed", sudoers: "not_asked" });
  });

  it("the password is in no argument of the spawn and in no variable but its own", async () => {
    const call = bootstrapCall({ sudoers: true });
    const password = call.password.toString();
    const spawns = scriptSeam(() => BASE_RESULT);
    await runBootstrap(call);
    const [at] = spawns as [AtSpawn];
    for (const word of at.argv) expectAbsent(word, password, "an argv word");
    for (const [name, value] of Object.entries(at.env)) {
      if (name !== "HARPOC_SSH_PASSWORD") expectAbsent(value, password, name);
    }
    expect(at.argv.length).toBe(59);
  });
});

describe("refuseWindowsVaultHost", () => {
  it.runIf(win32)("a Windows vault host is refused", async () => {
    const err = await expectVaultError(
      () => refuseWindowsVaultHost(),
      ErrorCode.SSH_CLIENT_UNSUPPORTED,
    );
    expect(err.message).toBe(
      "Unsupported ssh client: the ssh bootstrap is not served on a Windows vault host",
    );
  });

  it.skipIf(win32)("any other vault host passes", () => {
    expect(refuseWindowsVaultHost()).toBeUndefined();
  });
});
