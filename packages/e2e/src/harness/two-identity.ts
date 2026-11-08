import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, posix } from "node:path";
import { SESSION_FILE_NAME, VaultState } from "@harpoc/shared";
import type { ChildRun } from "./child.js";
import { resolveCliEntry } from "./fixtures.js";
import { PKI_DIR } from "./pki.js";
import { KEYS_DIR, clientKeyPem } from "./ssh.js";
import { privateKeyNeedles, startSsh2Server } from "./ssh2-server.js";
import type { Ssh2Server } from "./ssh2-server.js";
import { runAs, startAs } from "./sudo.js";
import type { AsUserOptions, StartedChild } from "./sudo.js";
import { startTlsEcho } from "./tls-echo.js";
import type { TlsEcho } from "./tls-echo.js";

/** In the argv of every command the suite starts as the agent user, so the teardown's sweep can name them. */
export const B6_MARKER = "harpoc-b6";
export const UNLOCK_CREDENTIAL_NAME = "harpoc-unlock";
/** The recipe's runtime directory (`deploy/linux/install-two-identity.sh`). */
export const DEFAULT_RUNTIME_DIR = "/run/harpoc";
/** The agent token's lifetime: a token file left behind dies within the hour. */
export const TOKEN_TTL_MINUTES = 60;

const ARGON2_TIMEOUT_MS = 110_000;
const SSH_AGENT_READY = /\[harpoc\] ssh-agent listening on /;
const API_KEY_HANDLE = "secret://api-key";
const SSH_KEY_HANDLE = "secret://deploy-key";
/** What `harpoc proxy env --json` may hand the agent's environment — sudo's argv is world-readable. */
const AGENT_ENV_NAMES: readonly string[] = [
  "HARPOC_PROXY_URL",
  "HARPOC_PROXY_BASE",
  "HARPOC_PROXY_SOCKET",
  "HARPOC_PROXY_TOKEN_FILE",
  "HARPOC_PLACEHOLDER_API_KEY",
];

/**
 * A user's HTTP client: the bearer read from `tokenFile` by the script itself,
 * so neither argv nor the runner ever holds the token.
 */
export const TOKEN_FILE_REQUEST = [
  "let input = '';",
  "process.stdin.on('data', (c) => (input += c));",
  "process.stdin.on('end', () => {",
  "  const { url, method, tokenFile, body } = JSON.parse(input);",
  "  const token = require('node:fs').readFileSync(tokenFile, 'utf8').trim();",
  "  const headers = { authorization: 'Bearer ' + token, 'content-type': 'application/json' };",
  "  fetch(url, { method, headers, body })",
  "    .then(async (res) => process.stdout.write(JSON.stringify({ status: res.status, body: await res.text() })))",
  "    .catch((err) => { process.stderr.write(String(err)); process.exitCode = 1; });",
  "});",
].join("\n");

/**
 * The agent's own launcher: runs each command (no shell) at once, and for one
 * marked `proxyAuthorization` writes `Proxy-Authorization: Bearer <token>` to
 * its stdin — the token read from `$HARPOC_PROXY_TOKEN_FILE`, curl's `-H @-`
 * recipe (`egress-proxy.md`) — then prints every result as one JSON line.
 */
export const AGENT_DRIVER = [
  `// ${B6_MARKER}-driver`,
  "const { spawn } = require('node:child_process');",
  "const { readFileSync } = require('node:fs');",
  "let input = '';",
  "process.stdin.on('data', (c) => (input += c));",
  "process.stdin.on('end', () => {",
  "  const { commands } = JSON.parse(input);",
  "  const header = () =>",
  "    'Proxy-Authorization: Bearer ' + readFileSync(process.env.HARPOC_PROXY_TOKEN_FILE, 'utf8').trim() + '\\n';",
  "  const runs = commands.map((c) => new Promise((resolve) => {",
  "    const child = spawn(c.command, c.args, { shell: false, stdio: ['pipe', 'pipe', 'pipe'] });",
  "    let stdout = '';",
  "    let stderr = '';",
  "    child.stdout.on('data', (d) => (stdout += d));",
  "    child.stderr.on('data', (d) => (stderr += d));",
  "    child.on('error', (err) => resolve({ code: null, stdout, stderr: stderr + String(err) }));",
  "    child.on('close', (code) => resolve({ code, stdout, stderr }));",
  "    child.stdin.on('error', () => undefined);",
  "    child.stdin.end(c.proxyAuthorization ? header() : '');",
  "  }));",
  "  Promise.all(runs).then((results) => process.stdout.write(JSON.stringify({ results })));",
  "});",
].join("\n");

/** Copies stdin into a new owner-only file at `argv[1]` — refusing one that exists. */
export const WRITE_STDIN_TO_FILE =
  "const fs = require('node:fs'); fs.writeFileSync(process.argv[1], fs.readFileSync(0), { mode: 0o600, flag: 'wx' });";

export interface ConsumerPaths {
  dir: string;
  tokenFile: string;
  proxySocket: string;
  agentSocket: string;
}

export interface DaemonPorts {
  rest: number;
  proxy: number;
}

export interface DriverCommand {
  command: string;
  args: string[];
  proxyAuthorization?: boolean;
}

export interface DriverResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

export interface FetchResult {
  status: number;
  body: string;
}

export interface AuditRow {
  id: number;
  event_type: string;
  success: boolean;
  principal_id: string | null;
  secret_id: string | null;
  detail: Record<string, unknown> | null;
}

export interface TwoIdentityOptions {
  vaultUser: string;
  agentUser: string;
  runtimeDir: string;
  password: string;
  apiKeyValue: string;
}

export interface TwoIdentityDeployment {
  vaultUser: string;
  agentUser: string;
  vaultDir: string;
  credentialsDir: string;
  runtimeDir: string;
  consumer: ConsumerPaths;
  restOrigin: string;
  proxyPort: number;
  /** No session file stood beside the vault when the daemon started: init's was erased by `lock`. */
  startedWithoutSession: boolean;
  echo: TlsEcho;
  sshServer: Ssh2Server;
  /** `harpoc proxy env --json` for the agent and the api key, and SSH_AUTH_SOCK: the agent's configuration. */
  agentEnv: Record<string, string>;
  /** The agent's known_hosts line and the client key's public half, readable by the agent. */
  agentFiles: { knownHosts: string; identity: string };
  handles: { apiKey: string; sshKey: string };
  placeholders: { apiKey: string };
  /** What no agent-visible channel may carry: the api key's value and the private key's needles. */
  credentials: { apiKeyValue: string; sshKeyNeedles: string[]; all: string[] };
  daemon: StartedChild;
  /** The built CLI in process as the vault user, on the vault directory (administration). */
  cli(args: string[], opts?: { stdin?: string; timeoutMs?: number }): Promise<ChildRun>;
  asVault(argv: string[], opts?: AsUserOptions): Promise<ChildRun>;
  asAgent(argv: string[], opts?: AsUserOptions): Promise<ChildRun>;
  /** `commands` launched by `AGENT_DRIVER` as the agent user, in `agentEnv`; settles with their results. */
  driveAgent(commands: DriverCommand[], timeoutMs?: number): Promise<DriverResult[]>;
  /** A REST request as the agent user with the token the daemon minted into its consumer directory. */
  agentFetch(method: "GET" | "POST", path: string, body?: unknown): Promise<FetchResult>;
  /** A REST request as the vault user with the observer's admin token (minted before the lock). */
  vaultFetch(method: "GET" | "POST", path: string): Promise<FetchResult>;
  auditRows(eventType: string): Promise<AuditRow[]>;
  /** The agent's current token, read as the agent — for boolean absence checks only. */
  agentToken(): Promise<string>;
  stop(): Promise<void>;
}

export function consumerPaths(runtimeDir: string, consumer: string): ConsumerPaths {
  const dir = posix.join(runtimeDir, consumer);
  return {
    dir,
    tokenFile: posix.join(dir, "token.jwt"),
    proxySocket: posix.join(dir, "proxy.sock"),
    agentSocket: posix.join(dir, "ssh-agent.sock"),
  };
}

/** The agent's `--issue-token` spec: a use-only token for the two handles (DB-13's grammar). */
export function issueTokenSpec(agent: string, file: string, ttlMinutes: number): string {
  return `agent=${agent},file=${file},scope=use,secrets=api-key+deploy-key,ttl=${String(ttlMinutes)}`;
}

/** The daemon: headless from the credential, memory session, REST, the proxy, the socket, the token file. */
export function daemonArgs(
  vaultDir: string,
  runtimeDir: string,
  agent: string,
  ports: DaemonPorts,
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
    "--unlock-credential",
    UNLOCK_CREDENTIAL_NAME,
    "--proxy",
    "--proxy-port",
    String(ports.proxy),
    "--ssh-agent",
    "--issue-token",
    issueTokenSpec(agent, consumerPaths(runtimeDir, agent).tokenFile, TOKEN_TTL_MINUTES),
  ];
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address() as AddressInfo;
      srv.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}

function expectExit(run: ChildRun, code: number, what: string): ChildRun {
  if (run.code !== code) {
    throw new Error(
      `${what}: exited ${String(run.code)}, not ${String(code)}: ${run.stderr.trim()}`,
    );
  }
  return run;
}

/** Runs every step, then throws the first failure: a teardown never stops at its first error. */
async function settleSteps(steps: Array<() => Promise<void>>): Promise<void> {
  const failures: unknown[] = [];
  for (const step of steps) {
    try {
      await step();
    } catch (err) {
      failures.push(err);
    }
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) throw new AggregateError(failures, "the deployment's teardown failed");
}

/**
 * Deployment model B on a real kernel (design M3, M4(i), M5, M1, M2): the
 * built CLI daemon as the vault user, started headless in memory mode from a
 * fake `$CREDENTIALS_DIRECTORY`, with REST, the egress proxy, the agent socket
 * and the agent's token file in the recipe's consumer directory; the agent user
 * holds only the placeholder, the socket path and that file. Every vault step
 * is the built CLI through `sudo -n -u <vault user>`, every agent action a
 * child through `sudo -n -u <agent user>` (integration's `two-identity.test.ts`
 * recipe). The upstreams run in this process: the TLS echo the secret's URL
 * allowlist and CA pin name, the ssh2 server its known-hosts pin names.
 */
export async function startTwoIdentityDeployment(
  options: TwoIdentityOptions,
): Promise<TwoIdentityDeployment> {
  const { vaultUser, agentUser, runtimeDir } = options;
  const cliEntry = resolveCliEntry();
  const consumer = consumerPaths(runtimeDir, agentUser);
  const held: {
    echo?: TlsEcho;
    sshServer?: Ssh2Server;
    agentDir?: string;
    root?: string;
    daemon?: StartedChild;
  } = {};

  const teardown = (): Promise<void> => {
    const steps: Array<() => Promise<void>> = [];
    const { daemon, root, echo, sshServer, agentDir } = held;
    if (daemon !== undefined) {
      steps.push(async () => {
        const code = await daemon.stop();
        if (code !== 0) throw new Error(`the model-B daemon exited ${String(code)} on SIGTERM`);
      });
      steps.push(async () => {
        const swept = await runAs(agentUser, ["pkill", "-KILL", "-u", agentUser, "-f", B6_MARKER]);
        expectExit(swept, 1, "a process the suite started as the agent user outlived its row");
      });
    }
    if (root !== undefined) {
      steps.push(async () => {
        expectExit(
          await runAs(vaultUser, ["rm", "-f", "--", consumer.tokenFile]),
          0,
          "removing the agent's token file",
        );
      });
      steps.push(async () => {
        const swept = await runAs(vaultUser, ["pkill", "-KILL", "-u", vaultUser, "-f", root]);
        expectExit(swept, 1, "a process of the vault user outlived the suite");
      });
      steps.push(async () => {
        expectExit(await runAs(vaultUser, ["rm", "-rf", "--", root]), 0, `removing ${root}`);
      });
    }
    if (echo !== undefined) steps.push(() => echo.close());
    if (sshServer !== undefined) steps.push(() => sshServer.close());
    if (agentDir !== undefined) {
      steps.push(async () => {
        rmSync(agentDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      });
    }
    return settleSteps(steps);
  };

  try {
    const echo = await startTlsEcho();
    held.echo = echo;
    const sshServer = await startSsh2Server();
    held.sshServer = sshServer;

    const agentDir = mkdtempSync(join(tmpdir(), `${B6_MARKER}-agent-`));
    held.agentDir = agentDir;
    chmodSync(agentDir, 0o755);
    const agentFiles = {
      knownHosts: posix.join(agentDir, "known_hosts"),
      identity: posix.join(agentDir, "identity.pub"),
    };
    writeFileSync(agentFiles.knownHosts, `${sshServer.knownHostLine}\n`);
    writeFileSync(agentFiles.identity, readFileSync(join(KEYS_DIR, "out", "client_ed25519.pub")));
    chmodSync(agentFiles.knownHosts, 0o644);
    chmodSync(agentFiles.identity, 0o644);

    const made = expectExit(
      await runAs(vaultUser, ["mktemp", "-d", posix.join(tmpdir(), `${B6_MARKER}-XXXXXX`)]),
      0,
      "mktemp as the vault user",
    );
    const root = made.stdout.trim();
    held.root = root;
    const vaultDir = posix.join(root, "vault");
    const credentialsDir = posix.join(root, "credentials");
    const adminTokenFile = posix.join(root, "admin.jwt");
    const keyCopy = posix.join(root, "deploy-key.pem");
    expectExit(
      await runAs(vaultUser, ["mkdir", "-m", "0700", "--", vaultDir, credentialsDir]),
      0,
      "the vault and credentials directories",
    );

    const asVault = (argv: string[], opts: AsUserOptions = {}): Promise<ChildRun> =>
      runAs(vaultUser, argv, opts);
    const asAgent = (argv: string[], opts: AsUserOptions = {}): Promise<ChildRun> =>
      runAs(agentUser, argv, opts);
    const cli = (args: string[], opts: { stdin?: string; timeoutMs?: number } = {}) =>
      asVault([process.execPath, cliEntry, "--vault-dir", vaultDir, ...args], {
        env: { HARPOC_SESSION_KEYSTORE: "off" },
        stdin: opts.stdin,
        timeoutMs: opts.timeoutMs,
        label: `harpoc ${args.slice(0, 2).join(" ")} as ${vaultUser}`,
      });
    const step = async (args: string[], stdin?: string, timeoutMs?: number): Promise<void> => {
      expectExit(await cli(args, { stdin, timeoutMs }), 0, `harpoc ${args.join(" ")}`);
    };

    // init leaves the vault unlocked with the administrator's session file; lock erases it below.
    await step(["init"], `${options.password}\n${options.password}\n`, ARGON2_TIMEOUT_MS);
    await step(["agent", "register", agentUser]);
    await step(["secret", "set", "api-key"], `${options.apiKeyValue}\n`);
    await step(["secret", "allow", API_KEY_HANDLE, "--url", `${echo.origin}/*`, "--proxy"]);
    await step([
      "secret",
      "connection",
      API_KEY_HANDLE,
      "--http-ca",
      join(PKI_DIR, "out", "ca.crt"),
    ]);
    // The fixture key is the runner's 0600 file: the vault user imports an owner-only copy, removed at once.
    expectExit(
      await asVault([process.execPath, "-e", WRITE_STDIN_TO_FILE, keyCopy], {
        stdin: clientKeyPem(),
      }),
      0,
      "the deploy key's copy",
    );
    await step(["secret", "set", "deploy-key", "--from-file", keyCopy]);
    expectExit(await asVault(["rm", "-f", "--", keyCopy]), 0, "removing the deploy key's copy");
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
        agentUser,
        "--permissions",
        "use",
      ]);
    }
    // The observer's bearer for the audit trail (no REST mint exists); the agent never sees it.
    await step([
      "auth",
      "token",
      "--scope",
      "admin",
      "--principal-type",
      "user",
      "--label",
      `${B6_MARKER} observer`,
      "--ttl",
      "120",
      "--out",
      adminTokenFile,
    ]);
    await step(
      ["unlock-key", "enroll", "--out", posix.join(credentialsDir, UNLOCK_CREDENTIAL_NAME)],
      `${options.password}\n`,
      ARGON2_TIMEOUT_MS,
    );
    await step(["lock"]);
    const sessionProbe = await asVault(["test", "-e", posix.join(vaultDir, SESSION_FILE_NAME)]);
    const startedWithoutSession = sessionProbe.code === 1;

    let ports: DaemonPorts | undefined;
    for (let attempt = 0; attempt < 3 && held.daemon === undefined; attempt++) {
      const rest = await freePort();
      let proxy = await freePort();
      while (proxy === rest) proxy = await freePort();
      const candidate = { rest, proxy };
      const started = startAs(
        vaultUser,
        [process.execPath, cliEntry, ...daemonArgs(vaultDir, runtimeDir, agentUser, candidate)],
        {
          env: { HARPOC_SESSION_KEYSTORE: "off", CREDENTIALS_DIRECTORY: credentialsDir },
          label: "the model-B daemon",
        },
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
      await asAgent([
        process.execPath,
        cliEntry,
        "proxy",
        "env",
        agentUser,
        API_KEY_HANDLE,
        "--runtime-dir",
        runtimeDir,
        "--proxy-port",
        String(ports.proxy),
        "--json",
      ]),
      0,
      "harpoc proxy env as the agent user",
    );
    const printedEnv = JSON.parse(printed.stdout) as Record<string, string>;
    const unexpected = Object.keys(printedEnv).filter((name) => !AGENT_ENV_NAMES.includes(name));
    if (unexpected.length > 0) {
      throw new Error(`harpoc proxy env printed unexpected variables: ${unexpected.join(", ")}`);
    }
    const agentEnv: Record<string, string> = {
      ...Object.fromEntries(
        Object.entries(printedEnv).filter(([name]) => AGENT_ENV_NAMES.includes(name)),
      ),
      SSH_AUTH_SOCK: consumer.agentSocket,
    };
    const placeholder = agentEnv["HARPOC_PLACEHOLDER_API_KEY"];
    if (placeholder === undefined)
      throw new Error("harpoc proxy env printed no HARPOC_PLACEHOLDER_API_KEY");

    const fetchAs = async (
      user: string,
      tokenFile: string,
      method: "GET" | "POST",
      path: string,
      body?: unknown,
    ): Promise<FetchResult> => {
      const run = await runAs(user, [process.execPath, "-e", TOKEN_FILE_REQUEST], {
        stdin: JSON.stringify({
          url: `${restOrigin}${path}`,
          method,
          tokenFile,
          body: body === undefined ? undefined : JSON.stringify(body),
        }),
        label: `${method} ${path} as ${user}`,
      });
      expectExit(run, 0, `${method} ${path} as ${user}`);
      return JSON.parse(run.stdout) as FetchResult;
    };
    const vaultFetch = (method: "GET" | "POST", path: string): Promise<FetchResult> =>
      fetchAs(vaultUser, adminTokenFile, method, path);
    const sshKeyNeedles = privateKeyNeedles(clientKeyPem());

    return {
      vaultUser,
      agentUser,
      vaultDir,
      credentialsDir,
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
        const run = await asAgent([process.execPath, "-e", AGENT_DRIVER], {
          env: agentEnv,
          stdin: JSON.stringify({ commands }),
          timeoutMs,
          label: "the agent's driver",
        });
        expectExit(run, 0, "the agent's driver");
        return (JSON.parse(run.stdout) as { results: DriverResult[] }).results;
      },
      agentFetch: (method, path, body) =>
        fetchAs(agentUser, consumer.tokenFile, method, path, body),
      vaultFetch,
      async auditRows(eventType: string): Promise<AuditRow[]> {
        const query = new URLSearchParams({ event_type: eventType, limit: "500" });
        const answer = await vaultFetch("GET", `/api/v1/audit?${query.toString()}`);
        if (answer.status !== 200)
          throw new Error(`GET /api/v1/audit answered ${String(answer.status)}`);
        return (JSON.parse(answer.body) as { data: AuditRow[] }).data;
      },
      async agentToken(): Promise<string> {
        const read = await asAgent(["cat", "--", consumer.tokenFile]);
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
