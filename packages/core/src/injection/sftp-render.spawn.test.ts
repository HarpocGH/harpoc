import { generateKeyPairSync, randomBytes, randomInt } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, posix } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import type { InjectionPolicy, RenderEntry } from "@harpoc/shared";
import {
  ErrorCode,
  maxUnixSocketPathBytes,
  RENDER_CONNECT_TIMEOUT_SEC,
  VaultError,
} from "@harpoc/shared";
import { expectAbsent } from "@harpoc/test-utils";
import { agentSocketAccepts } from "./__fixtures__/agent-socket.js";
import { serialized } from "./__fixtures__/serialized.js";
import { HOST_KEY, KEY_B } from "./__fixtures__/ssh-public-keys.js";
import { createSftpPeer, sftpFrame } from "./sftp/__fixtures__/sftp-peer.js";
import type { SftpPeer, SftpPeerSession } from "./sftp/__fixtures__/sftp-peer.js";
import { writeRemoteFile } from "./sftp/sftp-writer.js";
import type { RenderWritten } from "./sftp/sftp-writer.js";
import { runRender } from "./sftp-render.js";
import type { RenderControl, RenderPlan, RenderRun } from "./sftp-render.js";
import { EphemeralSshAgent } from "./ssh-agent/index.js";
import { redactCaptured, spawnDuplex } from "./spawn-captured.js";
import type { DuplexChild, SpawnCapturedResult, SpawnDuplexOptions } from "./spawn-captured.js";
import { sshSftpSubsystemArgs } from "./ssh-common.js";

vi.mock("./spawn-captured.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./spawn-captured.js")>();
  return { ...actual, spawnDuplex: vi.fn() };
});
vi.mock("./sftp/sftp-writer.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./sftp/sftp-writer.js")>();
  return { ...actual, writeRemoteFile: vi.fn(actual.writeRemoteFile) };
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

const { mkdtempSync: realMkdtempSync, writeFileSync: realWriteFileSync } =
  await vi.importActual<typeof import("node:fs")>("node:fs");

const win32 = process.platform === "win32";
const REMOTE_PATH = "/srv/app/app.env";
const NAMES_REFUSED = "host and user must be names of letters, digits, '.', '_' and '-'";
const TEMP_FILE_UNPREPARED = "a temporary file of the sftp render could not be prepared";
const HOST_KEY_UNREAD = "Vault corrupted: a render host key line does not parse";
const HOST_KEY_LINE = "Host key verification failed.";
const HOST_KEY_FAILED = `${HOST_KEY_LINE}\r\n`;
const CONNECTION_REFUSED = "ssh: connect to host host.example port 2222: Connection refused\r\n";
const MARKER = "HARPOC-T9-STREAM-MARKER";
const ALLOWED = "HARPOC_T9_ALLOWED";
const AMBIENT = "HARPOC_T9_AMBIENT";

const BASE_RESULT: SpawnCapturedResult = {
  exit_code: 0,
  stdout: "",
  stderr: "",
  timed_out: false,
  truncated: false,
  signal: null,
  spawn_failed: false,
  redacted: false,
};
const KILLED: Partial<SpawnCapturedResult> = {
  timed_out: true,
  exit_code: null,
  signal: "SIGKILL",
};
const BARE_SPAWN = { network_isolation: false, fs_isolation: false };

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
    ssh_bootstrap: null,
    render: { entries: [], approvals: [] },
    ...overrides,
  };
}

function renderEntry(overrides: Partial<RenderEntry> = {}): RenderEntry {
  return {
    name: "env",
    host: "host.example",
    port: 2222,
    user: "deploy",
    path: REMOTE_PATH,
    host_keys: [HOST_KEY, KEY_B],
    template: "{{secret://app/token}}",
    ...overrides,
  };
}

function renderPlan(overrides: Partial<RenderPlan> = {}): RenderPlan {
  return {
    sshPath: "/usr/bin/ssh",
    entry: renderEntry(),
    keyPem: makeKeyPem(),
    content: randomBytes(70_000),
    redact: [randomBytes(12).toString("base64url")],
    timeoutMs: 120_000,
    policy: policy(),
    ...overrides,
  };
}

function newControl(): { seal: AbortController; control: RenderControl } {
  const seal = new AbortController();
  return { seal, control: { signal: seal.signal, written: "no" } };
}

interface FakeChild extends DuplexChild {
  session: SftpPeerSession;
  end: Mock<() => void>;
  abort: Mock<() => void>;
  settle(raw: Partial<SpawnCapturedResult>): void;
}

/**
 * A `DuplexChild` speaking to a session of the SFTP peer: `end()` settles it with `onEnd`,
 * `abort()` as a kill unless `onAbort` is `null`; a consumer that throws settles it as a
 * kill, and nothing is delivered or written after the settle, as the seam does.
 */
function fakeChild(
  peer: SftpPeer,
  options: {
    onEnd?: Partial<SpawnCapturedResult>;
    onAbort?: Partial<SpawnCapturedResult> | null;
  } = {},
): FakeChild {
  const session = peer.connect();
  let resolveSettled: (result: SpawnCapturedResult) => void = () => undefined;
  const settled = new Promise<SpawnCapturedResult>((resolve) => {
    resolveSettled = resolve;
  });
  let done = false;
  const settle = (raw: Partial<SpawnCapturedResult>): void => {
    if (done) return;
    done = true;
    resolveSettled({ ...BASE_RESULT, ...raw });
  };
  return {
    session,
    settle,
    settled,
    write(chunk: Buffer): Promise<void> {
      if (!done) return session.write(chunk);
      chunk.fill(0);
      return Promise.resolve();
    },
    onData(consumer: (chunk: Buffer) => void): void {
      session.onData((chunk) => {
        if (done) return;
        try {
          consumer(chunk);
        } catch {
          settle(KILLED);
        }
      });
    },
    end: vi.fn(() => settle(options.onEnd ?? { exit_code: 0 })),
    abort: vi.fn(() => {
      if (options.onAbort !== null) settle(options.onAbort ?? KILLED);
    }),
  };
}

/** A child whose peer never answers `INIT` and which settles with `raw` when it arrives. */
function settlesFirst(raw: Partial<SpawnCapturedResult>): () => FakeChild {
  let child: FakeChild | undefined;
  const peer = createSftpPeer({
    faults: {
      init: () => {
        child?.settle(raw);
        return "silent";
      },
    },
  });
  return () => (child = fakeChild(peer));
}

interface AtSpawn {
  command: string;
  argv: string[];
  opts: SpawnDuplexOptions;
  env: Record<string, string>;
  redact: string[];
  knownHostsFile: string;
  globalFile: string;
  identityFile: string;
  knownHosts: string;
  globalKnownHosts: string;
  identity: string;
}

function optionPath(argv: string[], name: string): string {
  const word = argv.find((a) => a.startsWith(`${name}="`)) ?? "";
  return word.slice(name.length + 2, -1);
}

function scriptSeam(answer: (at: AtSpawn) => DuplexChild | Promise<DuplexChild>): AtSpawn[] {
  const spawns: AtSpawn[] = [];
  vi.mocked(spawnDuplex).mockImplementation(async (command, argv, opts) => {
    const knownHostsFile = optionPath(argv, "UserKnownHostsFile");
    const globalFile = optionPath(argv, "GlobalKnownHostsFile");
    const identityFile = argv[argv.indexOf("-i") + 1] as string;
    const at: AtSpawn = {
      command,
      argv: [...argv],
      opts,
      env: { ...opts.env },
      redact: [...(opts.redact ?? [])],
      knownHostsFile,
      globalFile,
      identityFile,
      knownHosts: readFileSync(knownHostsFile, "utf8"),
      globalKnownHosts: readFileSync(globalFile, "utf8"),
      identity: readFileSync(identityFile, "utf8"),
    };
    spawns.push(at);
    return answer(at);
  });
  return spawns;
}

function writtenChild(): () => FakeChild {
  return () => fakeChild(createSftpPeer());
}

/** In place of the writer: a consumer that throws at the peer's first reply, settled by its signal alone. */
const writerWithThrowingConsumer: typeof writeRemoteFile = (channel, _path, _content, signal) =>
  new Promise((resolve) => {
    signal.addEventListener(
      "abort",
      () =>
        resolve({
          written: "no",
          reason: signal.reason === "timeout" ? "timeout" : "connect",
        }),
      { once: true },
    );
    channel.onData(() => {
      throw new Error("the writer's own fault");
    });
    void channel.write(sftpFrame(1, 3));
  });

function notSpawned(run: RenderRun): VaultError {
  expect(run.kind).toBe("not_spawned");
  return (run as { error: VaultError }).error;
}

async function flushTicks(count: number): Promise<void> {
  for (let i = 0; i < count; i++) await new Promise<void>((resolve) => setImmediate(resolve));
}

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

/** A macOS runner's temporary root as `realpathSync` spells it, the longer of its two spellings. */
const DARWIN_TEMP_ROOT = `/private/var/folders/xx/${"x".repeat(30)}/T`;

let tempRoot: string;
let saved: { TMPDIR?: string; TMP?: string; TEMP?: string };

// The short prefix keeps the agent's socket inside darwin's 104-byte sun_path under its long $TMPDIR.
beforeEach(() => {
  tempRoot = mkdtempSync(join(tmpdir(), "harpoc-"));
  saved = overrideTempEnv(tempRoot);
  vi.mocked(spawnDuplex).mockReset();
  vi.mocked(mkdtempSync).mockClear();
});

afterEach(() => {
  restoreTempEnv(saved);
  vi.mocked(writeFileSync).mockReset();
  vi.mocked(mkdtempSync).mockReset();
  vi.mocked(rmSync).mockReset();
  rmSync(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

describe("the suite's temporary directory", () => {
  it("keeps the agent's socket within darwin's bound under a macOS runner's temporary root", () => {
    const socket = posix.join(
      DARWIN_TEMP_ROOT,
      basename(tempRoot),
      "harpoc-agent-XXXXXX",
      "agent.sock",
    );
    const bytes = Buffer.byteLength(socket);
    expect(
      bytes,
      `on a macOS runner the agent's socket would be ${socket}, ${String(bytes)} bytes`,
    ).toBeLessThanOrEqual(maxUnixSocketPathBytes("darwin"));
  });
});

describe("runRender", () => {
  it("the argv", async () => {
    const spawns = scriptSeam(writtenChild());
    const plan = renderPlan();
    await runRender(plan, newControl().control);
    await runRender(renderPlan({ entry: renderEntry({ port: 22 }) }), newControl().control);
    const [first, second] = spawns as [AtSpawn, AtSpawn];
    expect(first.command).toBe(plan.sshPath);
    expect(first.argv.length).toBe(39);
    expect(basename(first.knownHostsFile)).toBe("known_hosts");
    expect(basename(first.globalFile)).toBe("global_known_hosts");
    expect(basename(first.identityFile)).toBe("identity.pub");
    expect(first.argv.slice(0, 33)).toEqual(
      sshSftpSubsystemArgs(
        { file: first.knownHostsFile, globalFile: first.globalFile },
        first.identityFile,
        RENDER_CONNECT_TIMEOUT_SEC,
      ),
    );
    expect(first.argv.slice(33)).toEqual(["-p", "2222", "-s", "--", "deploy@host.example", "sftp"]);
    expect(second.argv.length).toBe(39);
    expect(second.argv.slice(33)).toEqual(["-p", "22", "-s", "--", "deploy@host.example", "sftp"]);
  });

  it("the host is lower-cased once, for the argv and the pin", async () => {
    const spawns = scriptSeam(writtenChild());
    await runRender(
      renderPlan({ entry: renderEntry({ host: "Host.Example" }) }),
      newControl().control,
    );
    const [at] = spawns as [AtSpawn];
    expect(at.argv.at(-2)).toBe("deploy@host.example");
    expect(at.knownHosts).toBe(`[host.example]:2222 ${HOST_KEY}\n[host.example]:2222 ${KEY_B}\n`);
  });

  it("the pin file holds the entry's keys and the global one is empty", async () => {
    const spawns = scriptSeam(writtenChild());
    await runRender(renderPlan(), newControl().control);
    await runRender(renderPlan({ entry: renderEntry({ port: 22 }) }), newControl().control);
    const [bracketed, bare] = spawns as [AtSpawn, AtSpawn];
    expect(bracketed.knownHosts).toBe(
      `[host.example]:2222 ${HOST_KEY}\n[host.example]:2222 ${KEY_B}\n`,
    );
    expect(bracketed.globalKnownHosts).toBe("");
    expect(dirname(bracketed.globalFile)).toBe(dirname(bracketed.knownHostsFile));
    expect(bare.knownHosts).toBe(`host.example ${HOST_KEY}\nhost.example ${KEY_B}\n`);
    expect(bare.globalKnownHosts).toBe("");
  });

  it("the identity file and the agent", async () => {
    const start = vi.spyOn(EphemeralSshAgent, "start");
    let acceptingAtSpawn = false;
    const spawns = scriptSeam(async (at) => {
      acceptingAtSpawn = await agentSocketAccepts(at.env.SSH_AUTH_SOCK as string);
      return fakeChild(createSftpPeer());
    });
    try {
      await runRender(renderPlan(), newControl().control);
      const agent = await (start.mock.results[0]?.value as Promise<EphemeralSshAgent>);
      const [at] = spawns as [AtSpawn];
      expect(basename(dirname(at.identityFile)).startsWith("harpoc-ssh-id-")).toBe(true);
      expect(at.identity).toBe(`${agent.publicKeyOpenssh}\n`);
      expect(at.env.SSH_AUTH_SOCK).toBe(agent.authSock);
      expect(acceptingAtSpawn).toBe(true);
      expect(await agentSocketAccepts(agent.authSock)).toBe(false);
    } finally {
      start.mockRestore();
    }
  });

  it("the environment", async () => {
    vi.stubEnv(ALLOWED, "allowed");
    vi.stubEnv(AMBIENT, "ambient");
    try {
      const spawns = scriptSeam(writtenChild());
      await runRender(
        renderPlan({ policy: policy({ env_allowlist: [ALLOWED] }) }),
        newControl().control,
      );
      const [at] = spawns as [AtSpawn];
      expect(Object.keys(at.env).sort()).toEqual(
        ["PATH", ...(win32 ? ["SystemRoot", "ProgramData"] : []), "SSH_AUTH_SOCK", ALLOWED].sort(),
      );
      expect(at.env[ALLOWED]).toBe("allowed");
      expect(AMBIENT in at.env).toBe(false);
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("the options", async () => {
    const spawns = scriptSeam(writtenChild());
    const off = renderPlan({ timeoutMs: 4_321 });
    const offList = [...off.redact];
    await runRender(off, newControl().control);
    await runRender(
      renderPlan({
        policy: policy({ network_isolation: true, fs_isolation: true, strict_tree_exit: true }),
      }),
      newControl().control,
    );
    const [first, second] = spawns as [AtSpawn, AtSpawn];
    expect(first.opts.timeoutMs).toBe(4_321);
    expect(first.redact).toEqual(offList);
    expect(first.opts.redact?.length).toBe(0);
    expect([
      first.opts.networkIsolation,
      first.opts.fsIsolation,
      first.opts.strictTreeExit,
    ]).toEqual([false, false, false]);
    expect([
      second.opts.networkIsolation,
      second.opts.fsIsolation,
      second.opts.strictTreeExit,
    ]).toEqual([true, true, true]);
    expect(second.opts.timeoutMs).toBe(120_000);
    expect("stdin" in first.opts).toBe(false);
  });

  it("the file is written", async () => {
    const peer = createSftpPeer();
    let child: FakeChild | undefined;
    scriptSeam(() => (child = fakeChild(peer)));
    const plan = renderPlan();
    const copy = Buffer.from(plan.content);
    const run = await runRender(plan, newControl().control);
    expect(run).toEqual({ kind: "ran", outcome: { written: "yes" }, spawn: BARE_SPAWN });
    const entry = peer.entry(REMOTE_PATH);
    expect(entry?.data.equals(copy)).toBe(true);
    expect(entry?.mode).toBe(0o600);
    expect(child?.end).toHaveBeenCalledTimes(1);
    expect(child?.abort).not.toHaveBeenCalled();
  });

  it("a writer that fails aborts the child", async () => {
    let child: FakeChild | undefined;
    scriptSeam(() => (child = fakeChild(createSftpPeer({ faults: { fsetstat: { status: 3 } } }))));
    const run = await runRender(renderPlan(), newControl().control);
    expect(run).toEqual({
      kind: "ran",
      outcome: { written: "no", reason: "mode" },
      spawn: BARE_SPAWN,
    });
    expect(child?.abort).toHaveBeenCalledTimes(1);
    expect(child?.end).not.toHaveBeenCalled();
  });

  it.each([
    ["ssh's host-key line", { exit_code: 255, stderr: HOST_KEY_FAILED }, "host_key"],
    ["a refused connection", { exit_code: 255, stderr: CONNECTION_REFUSED }, "connect"],
    ["its budget", KILLED, "timeout"],
    ["a client that did not start", { spawn_failed: true, exit_code: null }, "connect"],
  ] as const)("a child that settles first: %s", async (_name, raw, reason) => {
    scriptSeam(settlesFirst(raw));
    const run = await runRender(renderPlan(), newControl().control);
    expect(run).toEqual({ kind: "ran", outcome: { written: "no", reason }, spawn: BARE_SPAWN });
  });

  it("the outcome is read with the plan's redaction", async () => {
    const words = HOST_KEY_LINE.slice(0, -1).split(" ");
    const plan = renderPlan();
    plan.redact.push(words[randomInt(words.length)] as string);
    scriptSeam(
      settlesFirst({ exit_code: 255, stderr: redactCaptured(HOST_KEY_FAILED, [...plan.redact]) }),
    );
    const run = await runRender(plan, newControl().control);
    expect(run).toMatchObject({ kind: "ran", outcome: { written: "no", reason: "host_key" } });
  });

  describe("the seal", () => {
    it("aborted before the call: not_spawned, VAULT_LOCKED, nothing made", async () => {
      const { seal, control } = newControl();
      seal.abort();
      scriptSeam(writtenChild());
      const start = vi.spyOn(EphemeralSshAgent, "start");
      try {
        const run = await runRender(renderPlan(), control);
        expect(notSpawned(run).code).toBe(ErrorCode.VAULT_LOCKED);
        expect("spawn" in run).toBe(false);
        expect(vi.mocked(spawnDuplex)).not.toHaveBeenCalled();
        expect(start).not.toHaveBeenCalled();
        expect(vi.mocked(mkdtempSync)).not.toHaveBeenCalled();
        expect(readdirSync(tempRoot)).toEqual([]);
      } finally {
        start.mockRestore();
      }
    });

    it("aborted inside the agent's start: not_spawned, VAULT_LOCKED, the agent disposed", async () => {
      const realStart = EphemeralSshAgent.start.bind(EphemeralSshAgent);
      let started: EphemeralSshAgent | undefined;
      let entered: () => void = () => undefined;
      let release: () => void = () => undefined;
      const inside = new Promise<void>((resolve) => {
        entered = resolve;
      });
      const held = new Promise<void>((resolve) => {
        release = resolve;
      });
      const start = vi.spyOn(EphemeralSshAgent, "start").mockImplementation(async (pem) => {
        started = await realStart(pem);
        entered();
        await held;
        return started;
      });
      try {
        scriptSeam(writtenChild());
        const { seal, control } = newControl();
        const running = runRender(renderPlan(), control);
        await inside;
        seal.abort();
        release();
        const run = await running;
        expect(notSpawned(run).code).toBe(ErrorCode.VAULT_LOCKED);
        expect(vi.mocked(spawnDuplex)).not.toHaveBeenCalled();
        expect(await agentSocketAccepts((started as EphemeralSshAgent).authSock)).toBe(false);
        expect(readdirSync(tempRoot)).toEqual([]);
      } finally {
        start.mockRestore();
      }
    });

    it("aborted while the client spawns: the child is aborted once", async () => {
      const { seal, control } = newControl();
      let child: FakeChild | undefined;
      scriptSeam(() => {
        child = fakeChild(createSftpPeer());
        seal.abort();
        return child;
      });
      const run = await runRender(renderPlan(), control);
      expect(run).toEqual({
        kind: "ran",
        outcome: { written: "no", reason: "connect" },
        spawn: BARE_SPAWN,
      });
      expect(child?.abort).toHaveBeenCalledTimes(1);
      expect(child?.end).not.toHaveBeenCalled();
      expect(child?.session.requests).toEqual([]);
    });

    it("an aborted control ends the child and hands on no further frame", async () => {
      const { seal, control } = newControl();
      let atAbort: () => void = () => undefined;
      const aborted = new Promise<void>((resolve) => {
        atAbort = resolve;
      });
      const peer = createSftpPeer({
        faults: {
          write: (n) => {
            if (n === 1) {
              seal.abort();
              atAbort();
            }
            return undefined;
          },
        },
      });
      let child: FakeChild | undefined;
      scriptSeam(() => (child = fakeChild(peer, { onAbort: null })));
      const running = runRender(renderPlan(), control);
      await aborted;
      await flushTicks(2);
      const requests = (child as FakeChild).session.requests;
      expect(requests.at(-1)?.type).toBe(6);
      expect(requests.filter((r) => r.type === 6).length).toBe(1);
      expect(child?.abort).toHaveBeenCalledTimes(1);
      child?.settle(KILLED);
      const run = await running;
      expect(run).toEqual({
        kind: "ran",
        outcome: { written: "no", reason: "write" },
        spawn: BARE_SPAWN,
      });
    });
  });

  it("control.written follows the writer", async () => {
    function recordingControl(signal: AbortSignal): {
      control: RenderControl;
      heard: RenderWritten[];
    } {
      const heard: RenderWritten[] = [];
      let written: RenderWritten = "no";
      const control: RenderControl = {
        signal,
        get written() {
          return written;
        },
        set written(next: RenderWritten) {
          heard.push(next);
          written = next;
        },
      };
      return { control, heard };
    }

    scriptSeam(writtenChild());
    const yes = recordingControl(new AbortController().signal);
    expect(yes.control.written).toBe("no");
    await runRender(renderPlan(), yes.control);
    expect(yes.heard).toEqual(["unconfirmed", "yes"]);
    expect(yes.control.written).toBe("yes");

    scriptSeam(() => fakeChild(createSftpPeer({ faults: { "posix-rename": { status: 4 } } })));
    const refused = recordingControl(new AbortController().signal);
    const refusedRun = await runRender(renderPlan(), refused.control);
    expect(refusedRun).toMatchObject({ outcome: { written: "no", reason: "rename" } });
    expect(refused.heard).toEqual(["unconfirmed", "no"]);

    const seal = new AbortController();
    scriptSeam(() =>
      fakeChild(
        createSftpPeer({
          faults: {
            "posix-rename": () => {
              seal.abort();
              return "silent";
            },
          },
        }),
      ),
    );
    const sealed = recordingControl(seal.signal);
    const sealedRun = await runRender(renderPlan(), sealed.control);
    expect(sealedRun).toMatchObject({ outcome: { written: "unconfirmed", reason: "rename" } });
    expect(sealed.heard).toEqual(["unconfirmed"]);
    expect(sealed.control.written).toBe("unconfirmed");
  });

  it("a writer that rejects ends the child, and the call leaves with its fault only once the child has settled", async () => {
    const broke = new Error("the writer broke");
    vi.mocked(writeRemoteFile).mockImplementationOnce(() => Promise.reject(broke));
    let child: FakeChild | undefined;
    scriptSeam(() => (child = fakeChild(createSftpPeer(), { onAbort: null })));
    let left = false;
    const ending = runRender(renderPlan(), newControl().control).catch((err: unknown) => {
      left = true;
      return err;
    });
    await flushTicks(2);
    expect(child?.abort).toHaveBeenCalledTimes(1);
    expect(left).toBe(false);
    child?.settle(KILLED);
    expect(await ending).toBe(broke);
    expect(child?.end).not.toHaveBeenCalled();
  });

  it("a consumer that throws is a protocol fault, not a timeout", async () => {
    vi.mocked(writeRemoteFile).mockImplementationOnce(writerWithThrowingConsumer);
    let child: FakeChild | undefined;
    scriptSeam(() => (child = fakeChild(createSftpPeer())));
    const run = await runRender(renderPlan(), newControl().control);
    expect(run).toEqual({
      kind: "ran",
      outcome: { written: "no", reason: "protocol" },
      spawn: BARE_SPAWN,
    });
    expect(child?.abort).toHaveBeenCalledTimes(1);
    expect(child?.end).not.toHaveBeenCalled();
  });

  it("the seam's refusal", async () => {
    const refusal = VaultError.fsIsolationUnavailable("none");
    scriptSeam(() => Promise.reject(refusal));
    const run = await runRender(
      renderPlan({ policy: policy({ fs_isolation: true }) }),
      newControl().control,
    );
    expect(notSpawned(run)).toBe(refusal);
    expect((run as { spawn?: unknown }).spawn).toStrictEqual({
      network_isolation: false,
      fs_isolation: true,
    });

    const broke = new Error("seam broke");
    scriptSeam(() => Promise.reject(broke));
    await expect(runRender(renderPlan(), newControl().control)).rejects.toBe(broke);
  });

  it("a key the agent cannot load", async () => {
    scriptSeam(writtenChild());
    const run = await runRender(renderPlan({ keyPem: "not a key" }), newControl().control);
    expect(notSpawned(run).code).toBe(ErrorCode.SSH_AGENT_FAILED);
    expect("spawn" in run).toBe(false);
    expect(vi.mocked(spawnDuplex)).not.toHaveBeenCalled();
    expect(readdirSync(tempRoot)).toEqual([]);
  });

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
    scriptSeam(writtenChild());
    const run = await runRender(
      renderPlan({ entry: renderEntry(overrides) }),
      newControl().control,
    );
    const error = notSpawned(run);
    expect(error.code).toBe(ErrorCode.INVALID_SSH_CONFIG);
    expect(error.message).toBe(NAMES_REFUSED);
    expect("spawn" in run).toBe(false);
    expect(vi.mocked(spawnDuplex)).not.toHaveBeenCalled();
    expect(vi.mocked(mkdtempSync)).not.toHaveBeenCalled();
    expect(readdirSync(tempRoot)).toEqual([]);
  });

  it("a stored host-key line that does not read is not_spawned with VAULT_CORRUPTED", async () => {
    scriptSeam(writtenChild());
    const run = await runRender(
      renderPlan({ entry: renderEntry({ host_keys: [HOST_KEY, "ssh-ed25519 not-a-key"] }) }),
      newControl().control,
    );
    const error = notSpawned(run);
    expect(error.code).toBe(ErrorCode.VAULT_CORRUPTED);
    expect(error.message).toBe(HOST_KEY_UNREAD);
    expect("spawn" in run).toBe(false);
    expect(vi.mocked(spawnDuplex)).not.toHaveBeenCalled();
    expect(vi.mocked(mkdtempSync)).not.toHaveBeenCalled();
    expect(readdirSync(tempRoot)).toEqual([]);
  });

  it.each([
    ["the known-hosts directory", () => failMkdtemp("harpoc-ssh-")],
    ["the known-hosts file", () => failWrite("known_hosts")],
    ["the global known-hosts file", () => failWrite("global_known_hosts")],
    ["the identity's directory", () => failMkdtemp("harpoc-ssh-id-")],
    ["the identity's file", () => failWrite("identity.pub")],
  ] as const)(
    "a temporary file that cannot be written: %s is not_spawned with FILE_IO_ERROR, nothing left",
    async (_name, arm) => {
      scriptSeam(writtenChild());
      arm();
      const run = await runRender(renderPlan(), newControl().control);
      const error = notSpawned(run);
      expect(error.code).toBe(ErrorCode.FILE_IO_ERROR);
      expect(error.message).toBe(TEMP_FILE_UNPREPARED);
      expect("spawn" in run).toBe(false);
      expect(vi.mocked(spawnDuplex)).not.toHaveBeenCalled();
      expect(readdirSync(tempRoot)).toEqual([]);
    },
  );

  type RanPath = [
    name: string,
    answer: (seal: AbortController) => (at: AtSpawn) => DuplexChild | Promise<DuplexChild>,
    settles: "fulfilled" | "rejected",
  ];
  const RAN_PATHS: RanPath[] = [
    ["a written file", writtenChild, "fulfilled"],
    [
      "a writer's failure",
      () => () => fakeChild(createSftpPeer({ faults: { fsetstat: { status: 3 } } })),
      "fulfilled",
    ],
    [
      "a child that settled first",
      () => settlesFirst({ exit_code: 255, stderr: HOST_KEY_FAILED }),
      "fulfilled",
    ],
    ["a child cut by its budget, its request unanswered", () => settlesFirst(KILLED), "fulfilled"],
    [
      "a seal with a write in flight",
      (seal) => () =>
        fakeChild(
          createSftpPeer({
            faults: {
              write: (n) => {
                if (n === 1) seal.abort();
                return undefined;
              },
            },
          }),
        ),
      "fulfilled",
    ],
    [
      "a consumer that throws",
      () => {
        vi.mocked(writeRemoteFile).mockImplementationOnce(writerWithThrowingConsumer);
        return writtenChild();
      },
      "fulfilled",
    ],
    [
      "a writer that rejects",
      () => {
        vi.mocked(writeRemoteFile).mockImplementationOnce(() =>
          Promise.reject(new Error("the writer broke")),
        );
        return writtenChild();
      },
      "rejected",
    ],
    [
      "a seam that rejects with a VaultError",
      () => () => Promise.reject(VaultError.fsIsolationUnavailable("none")),
      "fulfilled",
    ],
    [
      "a seam that rejects with an Error",
      () => () => Promise.reject(new Error("seam broke")),
      "rejected",
    ],
  ];

  it.each(RAN_PATHS)(
    "every temporary file and the agent are gone afterwards: %s",
    async (_name, answer, settles) => {
      const { seal, control } = newControl();
      const spawns = scriptSeam(answer(seal));
      const [result] = await Promise.allSettled([runRender(renderPlan(), control)]);
      expect(result.status).toBe(settles);
      const [at] = spawns as [AtSpawn];
      expect(existsSync(dirname(at.knownHostsFile))).toBe(false);
      expect(existsSync(dirname(at.identityFile))).toBe(false);
      expect(await agentSocketAccepts(at.env.SSH_AUTH_SOCK as string)).toBe(false);
      expect(readdirSync(tempRoot)).toEqual([]);
    },
  );

  it.each<[string, (seal: AbortController) => void, Partial<RenderPlan>]>([
    ...RAN_PATHS.map(
      ([name, answer]): [string, (seal: AbortController) => void, Partial<RenderPlan>] => [
        name,
        (seal) => scriptSeam(answer(seal)),
        {},
      ],
    ),
    ["an invalid name", () => scriptSeam(writtenChild()), { entry: renderEntry({ user: "-l" }) }],
    [
      "a host-key line that does not read",
      () => scriptSeam(writtenChild()),
      { entry: renderEntry({ host_keys: ["not a key line"] }) },
    ],
    ["a key the agent cannot load", () => scriptSeam(writtenChild()), { keyPem: "not a key" }],
    [
      "a temporary file that cannot be written",
      () => {
        scriptSeam(writtenChild());
        failWrite("known_hosts");
      },
      {},
    ],
  ])(
    "the content is zeroed and the redaction list emptied on every path: %s",
    async (_name, arm, overrides) => {
      const { seal, control } = newControl();
      arm(seal);
      const plan = renderPlan(overrides);
      await Promise.allSettled([runRender(plan, control)]);
      expect(plan.content.every((b) => b === 0)).toBe(true);
      expect(plan.redact.length).toBe(0);
    },
  );

  it("the content is zeroed and the redaction list emptied on a seal", async () => {
    const { seal, control } = newControl();
    seal.abort();
    scriptSeam(writtenChild());
    const plan = renderPlan();
    const run = await runRender(plan, control);
    expect(notSpawned(run).code).toBe(ErrorCode.VAULT_LOCKED);
    expect(plan.content.every((b) => b === 0)).toBe(true);
    expect(plan.redact.length).toBe(0);
  });

  it("the spawn fields", async () => {
    scriptSeam(() =>
      fakeChild(createSftpPeer(), {
        onEnd: {
          exit_code: 3,
          truncated: true,
          redacted: true,
          isolation_mechanism: "bwrap",
          fs_isolation_mechanism: "landlock",
          descendant_sweep: { killed: 1, failed: false },
          tree_kill: "job",
          strict_tree_exit: true,
        },
      }),
    );
    const full = await runRender(
      renderPlan({
        policy: policy({ network_isolation: true, fs_isolation: true, strict_tree_exit: true }),
      }),
      newControl().control,
    );
    expect((full as { spawn?: unknown }).spawn).toStrictEqual({
      network_isolation: true,
      isolation_mechanism: "bwrap",
      fs_isolation: true,
      fs_isolation_mechanism: "landlock",
      sanitized: true,
      descendant_sweep: { killed: 1, failed: false },
      tree_kill: "job",
      strict_tree_exit: true,
    });
    scriptSeam(() =>
      fakeChild(createSftpPeer(), {
        onEnd: { exit_code: 0, isolation_mechanism: undefined, fs_isolation_mechanism: undefined },
      }),
    );
    const bare = await runRender(renderPlan(), newControl().control);
    expect((bare as { spawn?: unknown }).spawn).toStrictEqual(BARE_SPAWN);
  });

  it.each([
    ["a written file", () => fakeChild(createSftpPeer(), { onEnd: { stderr: `${MARKER}\n` } })],
    [
      "a writer's failure",
      () =>
        fakeChild(createSftpPeer({ faults: { fsetstat: { status: 3 } } }), {
          onAbort: { ...KILLED, stderr: `${MARKER}\n` },
        }),
    ],
    [
      "a child that settled first",
      () => settlesFirst({ exit_code: 255, stderr: `${MARKER}\r\n${HOST_KEY_FAILED}` })(),
    ],
  ] as const)("nothing of the error stream is returned: %s", async (_name, answer) => {
    scriptSeam(answer);
    const run = await runRender(renderPlan(), newControl().control);
    expect(run.kind).toBe("ran");
    expectAbsent(serialized(run), MARKER, "the run");
  });
});
