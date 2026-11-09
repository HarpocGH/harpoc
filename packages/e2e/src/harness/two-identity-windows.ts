import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { win32 } from "node:path";
import { SESSION_FILE_NAME, VaultState } from "@harpoc/shared";
import { B7_MARKER, listAccountProcesses } from "../assert/process-inventory-windows.js";
import type { ChildRun } from "./child.js";
import { resolveCliEntry } from "./fixtures.js";
import { PKI_DIR } from "./pki.js";
import { runAsWindows, startAsWindows, stopAs, systemPaths } from "./runas-windows.js";
import type { WindowsAccount, WindowsRunOptions } from "./runas-windows.js";
import { runCommand } from "./sudo.js";
import type { AsUserOptions, StartedChild } from "./sudo.js";
import { KEYS_DIR, clientKeyPem } from "./ssh.js";
import { privateKeyNeedles, startSsh2Server } from "./ssh2-server.js";
import type { Ssh2Server } from "./ssh2-server.js";
import { startTlsEcho } from "./tls-echo.js";
import type { TlsEcho } from "./tls-echo.js";
import {
  AGENT_DRIVER,
  B6_MARKER,
  TOKEN_FILE_REQUEST,
  TOKEN_TTL_MINUTES,
  WRITE_STDIN_TO_FILE,
  agentEnvironment,
  expectExit,
  freePort,
  issueTokenSpec,
  settleSteps,
} from "./two-identity.js";
import type {
  AuditRow,
  DaemonPorts,
  DriverCommand,
  DriverResult,
  FetchResult,
} from "./two-identity.js";

export { B7_MARKER };
export const ARGON2_TIMEOUT_MS = 110_000;

const SSH_AGENT_READY = /\[harpoc\] ssh-agent listening on /;
const API_KEY_HANDLE = "secret://api-key";
const SSH_KEY_HANDLE = "secret://deploy-key";
/** What `harpoc proxy env --json` may hand the agent's environment (no `HARPOC_PROXY_SOCKET`: Windows has no `proxy.sock`, RP-B7-7). */
export const AGENT_ENV_NAMES_WINDOWS: readonly string[] = [
  "HARPOC_PROXY_URL",
  "HARPOC_PROXY_BASE",
  "HARPOC_PROXY_TOKEN_FILE",
  "HARPOC_PLACEHOLDER_API_KEY",
  "HARPOC_PROXY_CA_FILE",
  "SSL_CERT_FILE",
  "NODE_EXTRA_CA_CERTS",
  "REQUESTS_CA_BUNDLE",
  "CURL_CA_BUNDLE",
  "GIT_SSL_CAINFO",
];

/** The Linux driver with the Windows marker: the agent's launcher is found by it like its tools. */
export const AGENT_DRIVER_WINDOWS = AGENT_DRIVER.replaceAll(B6_MARKER, B7_MARKER);

/** Node one-liners the vault and agent accounts run — the Windows mirror of `ls -A`, `cat`, `test -e` and `rm -f`. */
export const LIST_DIRECTORY =
  "process.stdout.write(require('node:fs').readdirSync(process.argv[1]).join('\\n'))";
export const READ_FILE = "process.stdout.write(require('node:fs').readFileSync(process.argv[1]))";
export const EXISTS_PROBE = "process.exit(require('node:fs').existsSync(process.argv[1]) ? 0 : 1)";
export const REMOVE_FILE = "require('node:fs').rmSync(process.argv[1], { force: true })";
/** `rm -rf` as the vault account: a file its owner-only access list keeps from the runner (the sealed key) goes with the tree. */
export const REMOVE_TREE =
  "require('node:fs').rmSync(process.argv[1], { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })";
/** A program's own report of what it was given: the agent's view of itself, names of variables and its argument vector. */
export const REPORT_SELF =
  "process.stdout.write(JSON.stringify({ env: process.env, argv: process.argv.slice(1) }))";

/** A one-liner as either account runs it: its own arguments first (each script reads `process.argv[1]` at most), the marker last, so the teardown's sweep reaches it. */
export function nodeOneLiner(script: string, ...args: string[]): string[] {
  return [process.execPath, "-e", script, ...args, B7_MARKER];
}

/** The agent's driver run from its file (`AGENT_DRIVER_WINDOWS` on a command line is over the 1024 characters `CreateProcessWithLogonW` takes), the marker last. */
export function agentDriverArgv(driverFile: string): string[] {
  return [process.execPath, driverFile, B7_MARKER];
}

/** The teardown's removal of the run's root: as the vault account first (`removeAsVault`, the sealed key is its alone) — a failure that leaves the root refuses there, naming its exit code — then as the runner for anything left. */
export async function removeVaultRoot(
  root: string,
  vaultUser: string,
  removeAsVault: () => Promise<ChildRun>,
): Promise<void> {
  const asOwner = await removeAsVault();
  if (asOwner.code !== 0 && existsSync(root)) {
    throw new Error(
      `${root}: removing it as ${vaultUser} exited ${String(asOwner.code)}, and the runner cannot remove what the vault account's access list keeps (the sealed key)`,
    );
  }
  rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  if (existsSync(root)) {
    throw new Error(
      `${root} outlived its removal (as ${vaultUser}: exit ${String(asOwner.code)}; then as the runner)`,
    );
  }
}

/** The built CLI as either account runs it: the marker as node's own `--title`, which the CLI's parser never sees. */
export function cliArgv(cliEntry: string, args: string[]): string[] {
  return [process.execPath, `--title=${B7_MARKER}`, cliEntry, ...args];
}

export interface WindowsConsumerPaths {
  dir: string;
  tokenFile: string;
  /** `\\.\pipe\harpoc-<consumer>-ssh-agent` (RP-B7-2: `agentSocketPipeName` in `cli/src/utils/runtime-dir.ts`). */
  agentPipe: string;
}

export interface TwoAccountOptions {
  vault: WindowsAccount;
  agent: WindowsAccount;
  runtimeDir: string;
  /** The recipe's vault directory, `%ProgramData%\harpoc\vault`: the run's own directory is made under it. */
  vaultRoot: string;
  /** Where the agent-readable files (known_hosts, the public key) go: a directory under `%ProgramData%`. */
  publicRoot: string;
  password: string;
  apiKeyValue: string;
}

export interface TwoAccountDeployment {
  vaultUser: string;
  agentUser: string;
  vaultDir: string;
  runtimeDir: string;
  consumer: WindowsConsumerPaths;
  restOrigin: string;
  proxyPort: number;
  startedWithoutSession: boolean;
  echo: TlsEcho;
  sshServer: Ssh2Server;
  agentEnv: Record<string, string>;
  agentFiles: { knownHosts: string; identity: string };
  handles: { apiKey: string; sshKey: string };
  placeholders: { apiKey: string };
  credentials: { apiKeyValue: string; sshKeyNeedles: string[]; all: string[] };
  daemon: StartedChild & { pid(): number | undefined };
  cli(args: string[], opts?: { stdin?: string; timeoutMs?: number }): Promise<ChildRun>;
  asVault(argv: string[], opts?: AsUserOptions): Promise<ChildRun>;
  asAgent(argv: string[], opts?: AsUserOptions): Promise<ChildRun>;
  driveAgent(commands: DriverCommand[], timeoutMs?: number): Promise<DriverResult[]>;
  agentFetch(method: "GET" | "POST", path: string, body?: unknown): Promise<FetchResult>;
  vaultFetch(method: "GET" | "POST", path: string): Promise<FetchResult>;
  auditRows(eventType: string): Promise<AuditRow[]>;
  agentToken(): Promise<string>;
  stop(): Promise<void>;
}

export function consumerPathsWindows(runtimeDir: string, consumer: string): WindowsConsumerPaths {
  const dir = win32.join(runtimeDir, consumer);
  return {
    dir,
    tokenFile: win32.join(dir, "token.jwt"),
    agentPipe: `\\\\.\\pipe\\harpoc-${consumer}-ssh-agent`,
  };
}

/** `%ProgramData%\harpoc\run`: RP-B7-3's default, refused when `ProgramData` is unset. */
export function defaultRuntimeDirWindows(programData = process.env["ProgramData"]): string {
  if (programData === undefined || programData === "") {
    throw new Error("defaultRuntimeDirWindows: ProgramData is not set");
  }
  return win32.join(programData, "harpoc", "run");
}

/** The daemon on Windows: headless from the DPAPI-sealed key, memory session, REST, the proxy's TCP listener, the pipe, the token file. */
export function daemonArgsWindows(
  vaultDir: string,
  runtimeDir: string,
  agent: string,
  ports: DaemonPorts,
  sealedKey: string,
): string[] {
  return [
    "--vault-dir",
    vaultDir,
    "server",
    "start",
    "--rest",
    "--port",
    String(ports.rest),
    "--runtime-dir",
    runtimeDir,
    "--session",
    "memory",
    "--unlock-key-dpapi",
    sealedKey,
    "--proxy",
    "--proxy-port",
    String(ports.proxy),
    "--ssh-agent",
    "--issue-token",
    issueTokenSpec(agent, consumerPathsWindows(runtimeDir, agent).tokenFile, TOKEN_TTL_MINUTES),
  ];
}

/** The agent's ssh on Windows: `ssh-common.ts`'s hardening list, forward-slash paths without quotes, the native client by its System32 path. */
export function sshArgsWindows(d: {
  agentFiles: TwoAccountDeployment["agentFiles"];
  sshServer: Pick<Ssh2Server, "port">;
}): string[] {
  return [
    "-F",
    "none",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    `UserKnownHostsFile=${d.agentFiles.knownHosts}`,
    "-o",
    "GlobalKnownHostsFile=none",
    "-o",
    "IdentitiesOnly=yes",
    "-i",
    d.agentFiles.identity,
    "-o",
    "BatchMode=yes",
    "-o",
    "PasswordAuthentication=no",
    "-o",
    "ConnectTimeout=15",
    "-v",
    "-n",
    "-p",
    String(d.sshServer.port),
    "-l",
    B7_MARKER,
    "--",
    "127.0.0.1",
    "true",
  ];
}

/** The agent's curl through the proxy's TCP listener: the placeholder as the bearer, the token on stdin (`-H @-`), the marker as its user agent. */
export function curlArgsWindows(
  d: Pick<TwoAccountDeployment, "placeholders">,
  url: string,
  extra: string[] = [],
): string[] {
  return [
    "-sS",
    "--user-agent",
    B7_MARKER,
    ...extra,
    "-H",
    "@-",
    "-H",
    `Authorization: Bearer ${d.placeholders.apiKey}`,
    url,
  ];
}

/** A forward-slash path: Win32-OpenSSH reads it, and an option value then needs no quoting. */
export function forwardSlashes(path: string): string {
  return path.replaceAll("\\", "/");
}

/**
 * Deployment model B on Windows (RE-B7-3): the built CLI daemon as the vault
 * account, started headless in memory mode from a DPAPI-sealed unlock key, with
 * REST, the proxy's loopback listener, the agent's pipe and its token file in
 * the recipe's consumer directory; the agent account's programs hold only the
 * placeholder, the pipe's name and that file. Every vault step is the built CLI
 * run as the vault account, every agent action a program run as the agent
 * account, both through `runas-windows.ts`'s launcher — the account's password
 * on its stdin, the child's environment built from a list, never the runner's.
 * The runner is an administrator (the account that created both): the harness
 * reads the directories and stops processes, and the agent's programs are the
 * observers. The upstreams run in this process, as the Linux fixture's.
 */
export async function startTwoAccountDeployment(
  options: TwoAccountOptions,
): Promise<TwoAccountDeployment> {
  const { vault, agent, runtimeDir } = options;
  if (!existsSync(options.vaultRoot)) {
    throw new Error(
      `startTwoAccountDeployment: the vault root ${options.vaultRoot} does not exist: run deploy/windows/install-two-identity.ps1 first (the fixture never creates the recipe's directories)`,
    );
  }
  const cliEntry = resolveCliEntry();
  const consumer = consumerPathsWindows(runtimeDir, agent.user);
  const held: {
    echo?: TlsEcho;
    sshServer?: Ssh2Server;
    publicRoot?: string;
    publicDir?: string;
    root?: string;
    daemon?: StartedChild & { pid(): number | undefined };
    lock?: () => Promise<void>;
  } = {};

  const asVault = (argv: string[], opts: AsUserOptions = {}): Promise<ChildRun> =>
    runAsWindows(vault, argv, opts as WindowsRunOptions);
  const asAgent = (argv: string[], opts: AsUserOptions = {}): Promise<ChildRun> =>
    runAsWindows(agent, argv, { ...opts, tempDir: held.publicDir } as WindowsRunOptions);

  const markedPids = async (
    read: (argv: string[]) => Promise<ChildRun>,
    marks: string[],
  ): Promise<number[]> =>
    (await listAccountProcesses(read))
      .filter((entry) => marks.some((mark) => entry.commandLine?.includes(mark) === true))
      .map((entry) => entry.pid);

  const teardown = (): Promise<void> => {
    const steps: Array<() => Promise<void>> = [];
    const { daemon, lock, root, echo, sshServer, publicRoot, publicDir } = held;
    if (daemon !== undefined) {
      if (lock !== undefined) {
        steps.push(async () => {
          if (!daemon.exited()) await lock();
        });
      }
      steps.push(async () => {
        await daemon.stop();
      });
      steps.push(async () => {
        const left = await markedPids((argv) => asAgent(argv), [B7_MARKER]);
        for (const pid of left) await stopAs(agent, pid);
        if (left.length > 0) {
          throw new Error("a process the suite started as the agent account outlived its row");
        }
      });
    }
    if (root !== undefined) {
      steps.push(async () => {
        rmSync(consumer.tokenFile, { force: true, maxRetries: 5, retryDelay: 100 });
      });
      steps.push(async () => {
        const left = await markedPids((argv) => asVault(argv), [root, B7_MARKER]);
        for (const pid of left) await stopAs(vault, pid);
        if (left.length > 0) throw new Error("a process of the vault account outlived the suite");
      });
      steps.push(() =>
        removeVaultRoot(root, vault.user, () =>
          asVault(nodeOneLiner(REMOVE_TREE, root), {
            label: `removing ${root} as ${vault.user}`,
          }),
        ),
      );
    }
    if (echo !== undefined) steps.push(() => echo.close());
    if (sshServer !== undefined) steps.push(() => sshServer.close());
    if (publicDir !== undefined) {
      steps.push(async () => {
        rmSync(publicDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      });
    }
    if (publicRoot !== undefined) {
      steps.push(async () => {
        rmSync(publicRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      });
    }
    return settleSteps(steps);
  };

  try {
    const echo = await startTlsEcho();
    held.echo = echo;
    const sshServer = await startSsh2Server();
    held.sshServer = sshServer;

    if (!existsSync(options.publicRoot)) {
      mkdirSync(options.publicRoot);
      held.publicRoot = options.publicRoot;
    }
    const publicDir = mkdtempSync(win32.join(options.publicRoot, `${B7_MARKER}-agent-`));
    held.publicDir = publicDir;
    const grant = await runCommand(
      systemPaths().icacls,
      [publicDir, "/grant", `${agent.user}:(OI)(CI)M`],
      { label: "icacls on the agent's directory" },
    );
    expectExit(grant, 0, "granting the agent its own directory");
    const agentFiles = {
      knownHosts: forwardSlashes(win32.join(publicDir, "known_hosts")),
      identity: forwardSlashes(win32.join(publicDir, "identity.pub")),
    };
    writeFileSync(agentFiles.knownHosts, `${sshServer.knownHostLine}\n`);
    writeFileSync(
      agentFiles.identity,
      readFileSync(win32.join(KEYS_DIR, "out", "client_ed25519.pub")),
    );
    const driverFile = win32.join(publicDir, "driver.cjs");
    writeFileSync(driverFile, AGENT_DRIVER_WINDOWS);

    const root = mkdtempSync(win32.join(options.vaultRoot, `${B7_MARKER}-`));
    held.root = root;
    const vaultDir = win32.join(root, "vault");
    const adminTokenFile = win32.join(root, "admin.jwt");
    const keyCopy = win32.join(root, "deploy-key.pem");
    const sealedKey = win32.join(root, "unlock.key.dpapi");
    mkdirSync(vaultDir);

    const cli = (args: string[], opts: { stdin?: string; timeoutMs?: number } = {}) =>
      asVault(cliArgv(cliEntry, ["--vault-dir", vaultDir, ...args]), {
        env: { HARPOC_SESSION_KEYSTORE: "off" },
        stdin: opts.stdin,
        timeoutMs: opts.timeoutMs,
        label: `harpoc ${args.slice(0, 2).join(" ")} as ${vault.user}`,
      });
    const step = async (args: string[], stdin?: string, timeoutMs?: number): Promise<void> => {
      expectExit(await cli(args, { stdin, timeoutMs }), 0, `harpoc ${args.join(" ")}`);
    };

    await step(["init"], `${options.password}\n${options.password}\n`, ARGON2_TIMEOUT_MS);
    await step(["agent", "register", agent.user]);
    await step(["secret", "set", "api-key"], `${options.apiKeyValue}\n`);
    await step(["secret", "allow", API_KEY_HANDLE, "--url", `${echo.origin}/*`, "--proxy"]);
    await step([
      "secret",
      "connection",
      API_KEY_HANDLE,
      "--http-ca",
      win32.join(PKI_DIR, "out", "ca.crt"),
    ]);
    expectExit(
      await asVault(nodeOneLiner(WRITE_STDIN_TO_FILE, keyCopy), {
        stdin: clientKeyPem(),
      }),
      0,
      "the deploy key's copy",
    );
    await step(["secret", "set", "deploy-key", "--from-file", keyCopy]);
    expectExit(
      await asVault(nodeOneLiner(REMOVE_FILE, keyCopy)),
      0,
      "removing the deploy key's copy",
    );
    await step(["secret", "connection", SSH_KEY_HANDLE, "--known-host", sshServer.knownHostLine]);
    await step(["secret", "allow", SSH_KEY_HANDLE, "--host", "127.0.0.1", "--ssh-agent-socket"]);
    for (const handle of [API_KEY_HANDLE, SSH_KEY_HANDLE]) {
      await step([
        "policy",
        "grant",
        handle,
        "--principal-type",
        "agent",
        "--principal-id",
        agent.user,
        "--permissions",
        "use",
      ]);
    }
    await step([
      "auth",
      "token",
      "--scope",
      "admin",
      "--principal-type",
      "user",
      "--label",
      `${B7_MARKER} observer`,
      "--ttl",
      "120",
      "--out",
      adminTokenFile,
    ]);
    await step(
      ["unlock-key", "enroll", "--out", sealedKey, "--dpapi"],
      `${options.password}\n`,
      ARGON2_TIMEOUT_MS,
    );
    await step(["lock"]);
    const sessionProbe = await asVault(
      nodeOneLiner(EXISTS_PROBE, win32.join(vaultDir, SESSION_FILE_NAME)),
    );
    const startedWithoutSession = sessionProbe.code === 1;

    let ports: DaemonPorts | undefined;
    for (let attempt = 0; attempt < 3 && held.daemon === undefined; attempt++) {
      const rest = await freePort();
      let proxy = await freePort();
      while (proxy === rest) proxy = await freePort();
      const candidate = { rest, proxy };
      const started = startAsWindows(
        vault,
        cliArgv(
          cliEntry,
          daemonArgsWindows(vaultDir, runtimeDir, agent.user, candidate, sealedKey),
        ),
        { env: { HARPOC_SESSION_KEYSTORE: "off" }, label: "the model-B daemon" },
      );
      try {
        await started.waitForStderr(SSH_AGENT_READY);
        held.daemon = started;
        ports = candidate;
      } catch (err) {
        const collided = started.exited() && /EADDRINUSE/.test(started.stderrSoFar());
        try {
          await started.stop();
        } catch (stopErr) {
          throw new AggregateError(
            [err, stopErr],
            `the model-B daemon did not start and its stop failed; stderr:\n${started.stderrSoFar()}`,
            { cause: stopErr },
          );
        }
        if (!collided) {
          throw new Error(`the model-B daemon did not start; stderr:\n${started.stderrSoFar()}`, {
            cause: err,
          });
        }
      }
    }
    const daemon = held.daemon;
    if (daemon === undefined || ports === undefined) {
      throw new Error("the model-B daemon did not bind in three attempts");
    }
    const restOrigin = `http://127.0.0.1:${String(ports.rest)}`;
    const fetchAs = async (
      account: WindowsAccount,
      tokenFile: string,
      method: "GET" | "POST",
      path: string,
      body?: unknown,
    ): Promise<FetchResult> => {
      const run = await runAsWindows(account, nodeOneLiner(TOKEN_FILE_REQUEST), {
        stdin: JSON.stringify({
          url: `${restOrigin}${path}`,
          method,
          tokenFile,
          body: body === undefined ? undefined : JSON.stringify(body),
        }),
        tempDir: account === agent ? publicDir : undefined,
        label: `${method} ${path} as ${account.user}`,
      });
      expectExit(run, 0, `${method} ${path} as ${account.user}`);
      return JSON.parse(run.stdout) as FetchResult;
    };
    const vaultFetch = (method: "GET" | "POST", path: string): Promise<FetchResult> =>
      fetchAs(vault, adminTokenFile, method, path);
    held.lock = async () => {
      const locked = await vaultFetch("POST", "/api/v1/vault/lock");
      if (locked.status !== 200) {
        throw new Error(`POST /api/v1/vault/lock answered ${String(locked.status)}`);
      }
    };
    const health = await fetch(`${restOrigin}/api/v1/health`, {
      signal: AbortSignal.timeout(5_000),
    });
    const state = ((await health.json()) as { data?: { state?: string } }).data?.state;
    if (state !== VaultState.UNLOCKED) {
      throw new Error(
        `the model-B daemon answers health ${String(health.status)} in state ${String(state)}`,
      );
    }

    const printed = expectExit(
      await asAgent(
        cliArgv(cliEntry, [
          "proxy",
          "env",
          agent.user,
          API_KEY_HANDLE,
          "--runtime-dir",
          runtimeDir,
          "--proxy-port",
          String(ports.proxy),
          "--json",
        ]),
      ),
      0,
      "harpoc proxy env as the agent account",
    );
    const agentEnv: Record<string, string> = {
      ...agentEnvironment(
        JSON.parse(printed.stdout) as Record<string, string>,
        AGENT_ENV_NAMES_WINDOWS,
      ),
      SSH_AUTH_SOCK: consumer.agentPipe,
    };
    const placeholder = agentEnv["HARPOC_PLACEHOLDER_API_KEY"];
    if (placeholder === undefined)
      throw new Error("harpoc proxy env printed no HARPOC_PLACEHOLDER_API_KEY");

    const sshKeyNeedles = privateKeyNeedles(clientKeyPem());

    return {
      vaultUser: vault.user,
      agentUser: agent.user,
      vaultDir,
      runtimeDir,
      consumer,
      restOrigin,
      proxyPort: ports.proxy,
      startedWithoutSession,
      echo,
      sshServer,
      agentEnv,
      agentFiles,
      handles: { apiKey: API_KEY_HANDLE, sshKey: SSH_KEY_HANDLE },
      placeholders: { apiKey: placeholder },
      credentials: {
        apiKeyValue: options.apiKeyValue,
        sshKeyNeedles,
        all: [options.apiKeyValue, ...sshKeyNeedles],
      },
      daemon,
      cli,
      asVault,
      asAgent,
      async driveAgent(commands, timeoutMs = 90_000): Promise<DriverResult[]> {
        const run = await asAgent(agentDriverArgv(driverFile), {
          env: agentEnv,
          stdin: JSON.stringify({ commands }),
          timeoutMs,
          label: "the agent's driver",
        });
        expectExit(run, 0, "the agent's driver");
        return (JSON.parse(run.stdout) as { results: DriverResult[] }).results;
      },
      agentFetch: (method, path, body) => fetchAs(agent, consumer.tokenFile, method, path, body),
      vaultFetch,
      async auditRows(eventType: string): Promise<AuditRow[]> {
        const query = new URLSearchParams({ event_type: eventType, limit: "500" });
        const answer = await vaultFetch("GET", `/api/v1/audit?${query.toString()}`);
        if (answer.status !== 200)
          throw new Error(`GET /api/v1/audit answered ${String(answer.status)}`);
        return (JSON.parse(answer.body) as { data: AuditRow[] }).data;
      },
      async agentToken(): Promise<string> {
        const read = await asAgent(nodeOneLiner(READ_FILE, consumer.tokenFile));
        if (read.code !== 0) throw new Error(`the agent cannot read ${consumer.tokenFile}`);
        return read.stdout.trim();
      },
      stop: teardown,
    };
  } catch (err) {
    try {
      await teardown();
    } catch (cleanup) {
      throw new AggregateError(
        [err, cleanup],
        "the deployment's setup failed, and so did its teardown",
        { cause: cleanup },
      );
    }
    throw err;
  }
}

/** The pinned native client paths the agent's tools are run by. */
export function agentTools(systemRoot?: string): { curl: string; ssh: string } {
  const { curl, ssh } = systemPaths(systemRoot);
  return { curl, ssh };
}
