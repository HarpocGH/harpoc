import { randomBytes } from "node:crypto";
import { posix } from "node:path";
import { vi } from "vitest";
import { controlledPathDirs, resolveExecutable } from "@harpoc/core";
import {
  AuditEventType,
  ErrorCode,
  SESSION_FILE_NAME,
  VAULT_DB_NAME,
  VaultState,
} from "@harpoc/shared";
import {
  judgeSweep,
  readProcEntry,
  sweepRecordText,
  sweepUserProcesses,
} from "../assert/proc-sweep.js";
import type { ProcEntry, ProcReader } from "../assert/proc-sweep.js";
import { scan } from "../assert/scan.js";
import { callEvidence } from "../evidence/calls.js";
import type { CallEvidence } from "../evidence/calls.js";
import type { ChildRun } from "../harness/child.js";
import { SSH2_EXEC_REPLY } from "../harness/ssh2-server.js";
import { runCommand } from "../harness/sudo.js";
import type { CallOutcome } from "../harness/surfaces/surface.js";
import { B6_MARKER } from "../harness/two-identity.js";
import type { AuditRow, DriverResult, TwoIdentityDeployment } from "../harness/two-identity.js";
import { createHarnessVault, storeSecret } from "../harness/vault.js";
import { Outcome } from "./scenario.js";
import type { OutcomeValue } from "./scenario.js";

/** The image the docker row runs — the fleet fixtures' own base; the job pulls it, the row never does. */
export const MODEL_B_DOCKER_IMAGE = "node:22-alpine";
/** The negative control's credential, in its own in-process model-A vault. */
export const NEGATIVE_CONTROL_VALUE = "b6-negative-control-value-4f1a";

const NEGATIVE_CONTROL_PASSWORD = "b6-negative-control-pw-1";
const REDACTED = "[REDACTED]";
const ENCODED_FORMS: readonly string[] = ["base64", "base64url", "hex", "hexUpper"];

const HEADLESS = "b-headless-fake-credential";
const VALUE_ROUTE = "b-two-uid-value-route";
const SESSION_FILE = "b-two-uid-session-file";
const PROXY = "b-proxy-exposure";
const ECHO_REDACTION = "b-proxy-echo-redaction";
const AGENT_SOCKET = "b-agent-socket-exposure";
const ENVIRON = "b-two-uid-environ";
const DOCKER = "b-docker-inspect";
const NEGATIVE = "b-negative-same-uid-environ";

/** Captures every call a verdict is judged on, each through `callEvidence` with the credentials given. */
export interface CallCapture {
  record(outcome: CallOutcome): CallOutcome;
  calls(): CallEvidence[];
}

export function captureCalls(...credentials: string[]): CallCapture {
  const captured: CallEvidence[] = [];
  return {
    record(outcome) {
      captured.push(callEvidence(outcome, ...credentials));
      return outcome;
    },
    calls: () => captured.map((call) => ({ ...call })),
  };
}

/**
 * One model-B row (RD-B6-1): a Harpoc arm with no variant — B's comparison is
 * model A against model B, so A's control is its own scenario id. `observe`
 * returns the outcome it saw, and throws "arm is not discriminating" where a
 * held outcome lacks its proof (`e2e-benchmarks.md` Rules).
 */
export interface ModelBScenario {
  scenario: string;
  context: string;
  surface: "two-identity" | "engine";
  /** The record's `interface`: the audit `detail.interface` the row's own rows are verified against. */
  interface: string;
  expected: OutcomeValue;
  needs?: "docker";
  observe(deployment: TwoIdentityDeployment, capture: CallCapture): Promise<OutcomeValue>;
}

export function sighted(credentials: string[], ...texts: string[]): boolean {
  return credentials.some((credential) => texts.some((text) => scan(credential, text).length > 0));
}

export function requireProofs(scenario: string, proofs: Record<string, boolean>): void {
  const missing = Object.entries(proofs)
    .filter(([, held]) => !held)
    .map(([name]) => name);
  if (missing.length > 0) {
    throw new Error(
      `arm is not discriminating: ${scenario} lacks its proof (${missing.join(", ")})`,
    );
  }
}

export function newRows(rows: AuditRow[], before: AuditRow[]): AuditRow[] {
  const seen = new Set(before.map((row) => row.id));
  return rows.filter((row) => !seen.has(row.id));
}

export function asOutcome(run: ChildRun | DriverResult): CallOutcome {
  return { ok: run.code === 0, text: run.stdout, stderr: run.stderr };
}

export async function unlockedHealth(
  d: TwoIdentityDeployment,
  capture: CallCapture,
): Promise<boolean> {
  const health = await fetch(`${d.restOrigin}/api/v1/health`, {
    signal: AbortSignal.timeout(5_000),
  });
  const text = await health.text();
  capture.record({ ok: health.ok, text });
  return (
    health.ok &&
    (JSON.parse(text) as { data?: { state?: string } }).data?.state === VaultState.UNLOCKED
  );
}

/** Settles once `arrival` does; throws if the agent's command ended first (it never reached the upstream). */
export async function untilArrived(
  arrival: Promise<unknown>,
  running: Promise<ChildRun | DriverResult[]>,
  what: string,
): Promise<void> {
  const first = await Promise.race([
    arrival.then(() => undefined),
    running.then((ended) => (Array.isArray(ended) ? ended : [ended]).map((r) => String(r.code))),
  ]);
  if (first !== undefined) {
    throw new Error(`${what} ended (code ${first.join(", ")}) before it reached the upstream`);
  }
}

function proxyBase(d: Pick<TwoIdentityDeployment, "agentEnv">): string {
  const base = d.agentEnv["HARPOC_PROXY_BASE"];
  if (base === undefined) throw new Error("harpoc proxy env printed no HARPOC_PROXY_BASE");
  return base;
}

/** The agent's curl: the placeholder as the bearer, the proxy token on stdin (`-H @-`), the marker as its user agent. */
function curlArgs(d: TwoIdentityDeployment, url: string, extra: string[] = []): string[] {
  return [
    "-sS",
    "--user-agent",
    B6_MARKER,
    ...extra,
    "-H",
    "@-",
    "-H",
    `Authorization: Bearer ${d.placeholders.apiKey}`,
    url,
  ];
}

function parsedOrUndefined(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function bodyAfterHeaders(stdout: string): { credential?: { raw?: unknown } | null } | undefined {
  return parsedOrUndefined(stdout.slice(stdout.lastIndexOf("\n") + 1)) as
    { credential?: { raw?: unknown } | null } | undefined;
}

/** The agent's ssh: `ssh-common.ts`'s hardening list, the agent socket from SSH_AUTH_SOCK, `-v` for the bind line. */
function sshArgs(d: TwoIdentityDeployment): string[] {
  return [
    "-F",
    "none",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    `UserKnownHostsFile="${d.agentFiles.knownHosts}"`,
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
    B6_MARKER,
    "--",
    "127.0.0.1",
    "true",
  ];
}

/**
 * The container's client: the token read from the read-only mount of the
 * consumer directory at the path `HARPOC_PROXY_TOKEN_FILE` names, the
 * placeholder from its environment — so the token is in neither `Config.Cmd`
 * nor `Config.Env`, and only the placeholder and paths are in `Config.Env`.
 */
export const CONTAINER_CLIENT = [
  `// ${B6_MARKER}-container`,
  "const { request } = require('node:http');",
  "const token = require('node:fs').readFileSync(process.env.HARPOC_PROXY_TOKEN_FILE, 'utf8').trim();",
  "const base = new URL(process.env.HARPOC_PROXY_BASE);",
  "const headers = {",
  "  authorization: 'Bearer ' + process.env.HARPOC_PLACEHOLDER_API_KEY,",
  "  'proxy-authorization': 'Bearer ' + token,",
  "};",
  "const req = request({ host: base.hostname, port: base.port, path: '/' + process.argv[1], headers }, (res) => {",
  "  let body = '';",
  "  res.on('data', (c) => (body += c));",
  "  res.on('end', () => process.stdout.write(JSON.stringify({ status: res.statusCode, body })));",
  "});",
  "req.on('error', (err) => { process.stderr.write(String(err.code)); process.exitCode = 1; });",
  "req.end();",
].join("\n");

/**
 * The agent's `docker run` (RD-B6-10 R3): the consumer directory mounted
 * read-only at its own path, the token's path — never the token — in the environment.
 */
export function dockerRunArgs(
  d: Pick<TwoIdentityDeployment, "placeholders" | "agentEnv"> & {
    consumer: Pick<TwoIdentityDeployment["consumer"], "dir" | "tokenFile">;
    echo: Pick<TwoIdentityDeployment["echo"], "port">;
  },
  uid: string,
  gid: string,
  name: string,
): string[] {
  return [
    "docker",
    "run",
    "--pull",
    "never",
    "--name",
    name,
    "--network",
    "host",
    "--user",
    `${uid}:${gid}`,
    "--mount",
    `type=bind,source=${d.consumer.dir},target=${d.consumer.dir},readonly`,
    "-e",
    `HARPOC_PLACEHOLDER_API_KEY=${d.placeholders.apiKey}`,
    "-e",
    `HARPOC_PROXY_BASE=${proxyBase(d)}`,
    "-e",
    `HARPOC_PROXY_TOKEN_FILE=${d.consumer.tokenFile}`,
    MODEL_B_DOCKER_IMAGE,
    "node",
    "-e",
    CONTAINER_CLIENT,
    `127.0.0.1:${String(d.echo.port)}/echo/held`,
  ];
}

async function observeHeadless(
  d: TwoIdentityDeployment,
  capture: CallCapture,
): Promise<OutcomeValue> {
  const unlocked = await unlockedHealth(d, capture);
  const unlocks = (await d.auditRows(AuditEventType.VAULT_UNLOCK)).filter(
    (row) => row.success && row.detail?.["method"] === "credential",
  );
  capture.record({ ok: true, text: JSON.stringify(unlocks) });
  const usesBefore = await d.auditRows(AuditEventType.SECRET_USE);
  const seen = d.echo.requests.length;
  const used = await d.agentFetch("POST", "/api/v1/secrets/api-key/use", {
    action: {
      type: "http",
      method: "GET",
      url: `${d.echo.origin}/echo`,
      injection: { type: "bearer" },
    },
  });
  capture.record({ ok: used.status === 200, text: used.body });
  const uses = newRows(await d.auditRows(AuditEventType.SECRET_USE), usesBefore);
  capture.record({ ok: true, text: JSON.stringify(uses) });
  if (sighted(d.credentials.all, used.body)) return Outcome.LEAKED;
  if (used.status !== 200) return Outcome.BLOCKED;
  const result = (JSON.parse(used.body) as { data?: { status?: number; body?: string } }).data;
  requireProofs(HEADLESS, {
    noSessionAtStart: d.startedWithoutSession,
    unlocked,
    credentialUnlock: unlocks.length === 1,
    firstUse: usesBefore.length === 0,
    upstreamAnswered: result?.status === 200,
    upstreamReceivedCredential: d.echo.requests
      .slice(seen)
      .some((r) => r.path === "/echo" && r.authorization === `Bearer ${d.credentials.apiKeyValue}`),
    responseRedacted: (result?.body ?? "").includes(REDACTED),
    attributed:
      uses.length === 1 &&
      uses[0]?.success === true &&
      uses[0]?.principal_id === d.agentUser &&
      uses[0]?.detail?.["context"] === "http" &&
      uses[0]?.detail?.["interface"] === "rest",
  });
  return Outcome.SUCCEEDED;
}

async function observeValueRoute(
  d: TwoIdentityDeployment,
  capture: CallCapture,
): Promise<OutcomeValue> {
  const before = await d.auditRows(AuditEventType.ACCESS_DENIED);
  const answer = await d.agentFetch("GET", "/api/v1/secrets/api-key/value");
  capture.record({ ok: answer.status === 200, text: answer.body });
  const denied = newRows(await d.auditRows(AuditEventType.ACCESS_DENIED), before).filter(
    (row) => row.detail?.["operation"] === "GET /api/v1/secrets/api-key/value",
  );
  capture.record({ ok: true, text: JSON.stringify(denied) });
  if (answer.status === 200 || sighted(d.credentials.all, answer.body)) return Outcome.LEAKED;
  const body = JSON.parse(answer.body) as { error?: string; message?: string };
  requireProofs(VALUE_ROUTE, {
    forbidden: answer.status === 403,
    accessDenied: body.error === ErrorCode.ACCESS_DENIED,
    byScope: body.message === "Access denied: Token lacks permission: read",
    oneRow:
      denied.length === 1 &&
      denied[0]?.principal_id === d.agentUser &&
      denied[0]?.detail?.["interface"] === "rest",
  });
  return Outcome.BLOCKED;
}

async function observeSessionFile(
  d: TwoIdentityDeployment,
  capture: CallCapture,
): Promise<OutcomeValue> {
  const listing = await d.asVault(["ls", "-A", "--", d.vaultDir]);
  capture.record(asOutcome(listing));
  const names = listing.stdout.split("\n").filter((name) => name !== "");
  const agentList = await d.asAgent(["ls", "-A", "--", d.vaultDir]);
  capture.record(asOutcome(agentList));
  const agentRead = await d.asAgent(["cat", "--", posix.join(d.vaultDir, SESSION_FILE_NAME)]);
  // Boolean-shaped: a failing row never echoes a session file into a record or a log.
  capture.record({
    ok: agentRead.code === 0,
    text: `bytes read: ${String(agentRead.stdout.length)}`,
    stderr: agentRead.stderr,
  });
  const unlocked = await unlockedHealth(d, capture);
  if (agentRead.stdout.length > 0) return Outcome.LEAKED;
  if (agentList.code === 0) return Outcome.BYPASSED;
  if (names.includes(SESSION_FILE_NAME)) return Outcome.BLOCKED;
  requireProofs(SESSION_FILE, {
    vaultListed: listing.code === 0 && names.includes(VAULT_DB_NAME),
    daemonUnlocked: unlocked,
    agentRefused: /Permission denied/.test(agentList.stderr),
  });
  return Outcome.CHANNEL_ABSENT;
}

async function observeProxy(d: TwoIdentityDeployment, capture: CallCapture): Promise<OutcomeValue> {
  const before = await d.auditRows(AuditEventType.SECRET_USE);
  const seen = d.echo.requests.length;
  const [curl] = await d.driveAgent([
    {
      command: "curl",
      args: curlArgs(d, `http://127.0.0.1/127.0.0.1:${String(d.echo.port)}/echo/raw`, [
        "-D",
        "-",
        "--unix-socket",
        d.consumer.proxySocket,
      ]),
      proxyAuthorization: true,
    },
  ]);
  if (curl === undefined) throw new Error("the agent's driver returned no result for curl");
  capture.record(asOutcome(curl));
  const rows = newRows(await d.auditRows(AuditEventType.SECRET_USE), before).filter(
    (row) => row.detail?.["context"] === "proxy",
  );
  capture.record({ ok: true, text: JSON.stringify(rows) });
  if (sighted(d.credentials.all, curl.stdout, curl.stderr)) return Outcome.LEAKED;
  const upstream = d.echo.requests.slice(seen).filter((r) => r.path === "/echo/raw");
  requireProofs(PROXY, {
    completed: curl.code === 0 && /^HTTP\/1\.1 200/m.test(curl.stdout),
    brokered:
      upstream.length === 1 && upstream[0]?.authorization === `Bearer ${d.credentials.apiKeyValue}`,
    bodyRedacted: curl.stdout.includes(`"raw":"${REDACTED}"`),
    headerRedacted: /^x-echo-credential: \[REDACTED\]\r?$/im.test(curl.stdout),
    attributed:
      rows.length === 1 &&
      rows[0]?.success === true &&
      rows[0]?.principal_id === d.agentUser &&
      rows[0]?.detail?.["interface"] === "proxy" &&
      rows[0]?.detail?.["path"] === "/echo/raw" &&
      rows[0]?.detail?.["sanitized"] === true,
  });
  return Outcome.OPAQUE;
}

async function observeProxyEchoRedaction(
  d: TwoIdentityDeployment,
  capture: CallCapture,
): Promise<OutcomeValue> {
  const before = await d.auditRows(AuditEventType.SECRET_USE);
  const seen = d.echo.requests.length;
  const [curl] = await d.driveAgent([
    {
      command: "curl",
      args: curlArgs(d, `${proxyBase(d)}127.0.0.1:${String(d.echo.port)}/echo`, ["-D", "-"]),
      proxyAuthorization: true,
    },
  ]);
  if (curl === undefined) throw new Error("the agent's driver returned no result for curl");
  capture.record(asOutcome(curl));
  const rows = newRows(await d.auditRows(AuditEventType.SECRET_USE), before).filter(
    (row) => row.detail?.["context"] === "proxy",
  );
  capture.record({ ok: true, text: JSON.stringify(rows) });
  const body = bodyAfterHeaders(curl.stdout);
  const labels = [...new Set(scan(d.credentials.apiKeyValue, body).map((s) => s.encoding))];
  const raw = (label: string): boolean => label === "raw" || label.startsWith("raw+");
  if (
    labels.some(raw) ||
    scan(d.credentials.apiKeyValue, curl.stdout).some((s) => raw(s.encoding)) ||
    sighted(d.credentials.all, curl.stderr)
  ) {
    return Outcome.LEAKED;
  }
  const upstream = d.echo.requests.slice(seen).filter((r) => r.path === "/echo");
  requireProofs(ECHO_REDACTION, {
    answered200: curl.code === 0 && curl.stdout.startsWith("HTTP/1.1 200"),
    oneEchoRequest:
      upstream.length === 1 && upstream[0]?.authorization === `Bearer ${d.credentials.apiKeyValue}`,
    rawRedacted: body?.credential?.raw === REDACTED,
    headerRedacted: /^x-echo-credential: \[REDACTED\]\r?$/im.test(curl.stdout),
    useRow:
      rows.length === 1 &&
      rows[0]?.success === true &&
      rows[0]?.principal_id === d.agentUser &&
      rows[0]?.detail?.["interface"] === "proxy" &&
      rows[0]?.detail?.["path"] === "/echo" &&
      rows[0]?.detail?.["sanitized"] === true,
  });
  if (labels.length === 0) return Outcome.OPAQUE;
  requireProofs(ECHO_REDACTION, {
    encodedFormsOnly: labels.every((label) => ENCODED_FORMS.includes(label)),
    sighted: labels.length >= 1,
  });
  return Outcome.BYPASSED;
}

async function observeAgentSocket(
  d: TwoIdentityDeployment,
  capture: CallCapture,
): Promise<OutcomeValue> {
  const before = await d.auditRows(AuditEventType.SECRET_USE);
  const seen = d.sshServer.events.length;
  const run = await d.asAgent(["ssh", ...sshArgs(d)], {
    env: { SSH_AUTH_SOCK: d.consumer.agentSocket },
    timeoutMs: 60_000,
  });
  capture.record(asOutcome(run));
  const rows = newRows(await d.auditRows(AuditEventType.SECRET_USE), before).filter(
    (row) => row.detail?.["context"] === "ssh_agent",
  );
  capture.record({ ok: true, text: JSON.stringify(rows) });
  if (sighted(d.credentials.all, run.stdout, run.stderr)) return Outcome.LEAKED;
  requireProofs(AGENT_SOCKET, {
    completed: run.code === 0 && run.stdout.trim() === SSH2_EXEC_REPLY,
    bound: run.stderr.includes("bound agent to hostkey"),
    signatureVerified: d.sshServer.events
      .slice(seen)
      .some((e) => e.method === "publickey" && e.signed && e.verified),
    attributed:
      rows.length === 1 &&
      rows[0]?.success === true &&
      rows[0]?.principal_id === d.agentUser &&
      rows[0]?.detail?.["interface"] === "ssh_agent" &&
      rows[0]?.detail?.["host"] === "127.0.0.1" &&
      rows[0]?.detail?.["key_type"] === "ssh-ed25519",
  });
  return Outcome.OPAQUE;
}

async function observeEnviron(
  d: TwoIdentityDeployment,
  capture: CallCapture,
): Promise<OutcomeValue> {
  const judged = {
    credentials: d.credentials.all,
    placeholders: [d.placeholders.apiKey, d.consumer.agentSocket],
  };
  const echoHold = d.echo.hold();
  const sshHold = d.sshServer.hold();
  const driving = d.driveAgent([
    {
      command: "curl",
      args: curlArgs(d, `${proxyBase(d)}127.0.0.1:${String(d.echo.port)}/echo/held`),
      proxyAuthorization: true,
    },
    { command: "ssh", args: sshArgs(d) },
  ]);
  let entries: ProcEntry[];
  try {
    await untilArrived(
      Promise.all([echoHold.arrived, sshHold.arrived]),
      driving,
      "the agent's curl and ssh",
    );
    entries = await sweepUserProcesses(d.agentUser, (argv) => d.asAgent(argv));
  } finally {
    echoHold.release();
    sshHold.release();
    void driving.catch(() => undefined);
  }
  const results = await driving;
  const verdict = judgeSweep(entries, judged);
  for (const entry of entries) capture.record({ ok: true, text: sweepRecordText(entry, judged) });
  for (const result of results) capture.record(asOutcome(result));
  if (verdict.credentialSeen) return Outcome.LEAKED;
  if (sighted(d.credentials.all, ...results.flatMap((r) => [r.stdout, r.stderr]))) {
    return Outcome.LEAKED;
  }
  requireProofs(ENVIRON, {
    placeholderSwept: verdict.placeholderSeen,
    curlSwept: verdict.commands.includes("curl"),
    sshSwept: verdict.commands.includes("ssh"),
    toolsCompleted: results.length === 2 && results.every((r) => r.code === 0),
  });
  return Outcome.HANDLE_ONLY;
}

async function observeDocker(
  d: TwoIdentityDeployment,
  capture: CallCapture,
): Promise<OutcomeValue> {
  const idOf = async (flag: "-u" | "-g"): Promise<string> => {
    const run = await d.asAgent(["id", flag]);
    if (run.code !== 0) throw new Error(`id ${flag} as ${d.agentUser} exited ${String(run.code)}`);
    return run.stdout.trim();
  };
  const uid = await idOf("-u");
  const gid = await idOf("-g");
  const name = `${B6_MARKER}-${randomBytes(4).toString("hex")}`;
  const hold = d.echo.hold();
  const seen = d.echo.requests.length;
  const running = d.asAgent(dockerRunArgs(d, uid, gid, name), {
    timeoutMs: 90_000,
    label: `docker run ${name}`,
  });
  let inspected: ChildRun;
  let ran: ChildRun;
  let removed: ChildRun;
  try {
    try {
      await untilArrived(hold.arrived, running, "the container's brokered call");
      inspected = await d.asAgent(["docker", "inspect", name]);
    } finally {
      hold.release();
      void running.catch(() => undefined);
    }
    ran = await running;
  } finally {
    removed = await d.asAgent(["docker", "rm", "-f", name]);
  }
  if (removed.code !== 0 && !/No such container/.test(removed.stderr)) {
    throw new Error(`docker rm -f ${name} exited ${String(removed.code)}`);
  }
  capture.record(asOutcome(inspected));
  capture.record(asOutcome(ran));
  if (sighted(d.credentials.all, inspected.stdout, ran.stdout, ran.stderr)) return Outcome.LEAKED;
  const container = (
    parsedOrUndefined(inspected.stdout) as
      | Array<{
          Config?: { Env?: string[] };
          Mounts?: Array<{ Type?: string; Source?: string; Destination?: string; RW?: boolean }>;
        }>
      | undefined
  )?.[0];
  const mounts = container?.Mounts ?? [];
  const answer = parsedOrUndefined(ran.stdout) as { status?: number } | null | undefined;
  requireProofs(DOCKER, {
    inspected: inspected.code === 0,
    placeholderInEnv: (container?.Config?.Env ?? []).includes(
      `HARPOC_PLACEHOLDER_API_KEY=${d.placeholders.apiKey}`,
    ),
    consumerDirectoryReadOnly:
      mounts.length === 1 &&
      mounts[0]?.Type === "bind" &&
      mounts[0]?.Source === d.consumer.dir &&
      mounts[0]?.Destination === d.consumer.dir &&
      mounts[0]?.RW === false,
    completed: ran.code === 0 && answer?.status === 200,
    brokered: d.echo.requests
      .slice(seen)
      .some(
        (r) => r.path === "/echo/held" && r.authorization === `Bearer ${d.credentials.apiKeyValue}`,
      ),
  });
  return Outcome.HANDLE_ONLY;
}

async function observeNegativeControl(
  _d: TwoIdentityDeployment,
  capture: CallCapture,
): Promise<OutcomeValue> {
  const sleep = resolveExecutable("sleep", controlledPathDirs());
  if (sleep === null) throw new Error("no sleep binary on PATH");
  const read: ProcReader = (argv) =>
    runCommand(argv[0] ?? "", argv.slice(1), { label: argv.join(" ") });
  const judged = { credentials: [NEGATIVE_CONTROL_VALUE], placeholders: [] };
  const vault = await createHarnessVault(NEGATIVE_CONTROL_PASSWORD);
  try {
    const handle = await storeSecret(vault, "b6-negative-control", NEGATIVE_CONTROL_VALUE);
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [],
      command_allowlist: [sleep],
      env_allowlist: [],
      host_allowlist: [],
    });
    const using = vault.engine.useSecret(handle, {
      type: "process",
      command: sleep,
      args: ["60"],
      env_var: "API_KEY",
      timeout_ms: 90_000,
    });
    // Marks the call handled for a failure path that never reaches the await below.
    using.catch(() => undefined);
    let entry: ProcEntry | undefined;
    try {
      const pid = await vi.waitFor(
        async () => {
          const listed = await read(["pgrep", "-P", String(process.pid), "-x", "sleep"]);
          const pids = listed.stdout.split("\n").filter((line) => line.trim() !== "");
          if (pids.length !== 1) throw new Error(`${String(pids.length)} sleep children, not one`);
          return Number(pids[0]);
        },
        { timeout: 20_000, interval: 250 },
      );
      entry = await readProcEntry(pid, read);
    } finally {
      await read(["pkill", "-TERM", "-P", String(process.pid), "-x", "sleep"]);
    }
    const result = await using;
    if (entry === undefined)
      throw new Error("the process-context child exited before the sweep read it");
    capture.record({ ok: true, text: sweepRecordText(entry, judged) });
    capture.record({ ok: true, text: JSON.stringify(result) });
    return judgeSweep([entry], judged).credentialSeen ? Outcome.LEAKED : Outcome.OPAQUE;
  } finally {
    await vault.destroy();
  }
}

/**
 * The nine model-B rows, in run order: the headless row first, so its
 * `use_secret` is the daemon's first; the negative control last, on its own
 * in-process vault.
 */
export const MODEL_B_SCENARIOS: ModelBScenario[] = [
  {
    scenario: HEADLESS,
    context: "http",
    surface: "two-identity",
    interface: "rest",
    expected: Outcome.SUCCEEDED,
    observe: observeHeadless,
  },
  {
    scenario: VALUE_ROUTE,
    context: "rest",
    surface: "two-identity",
    interface: "rest",
    expected: Outcome.BLOCKED,
    observe: observeValueRoute,
  },
  {
    scenario: SESSION_FILE,
    context: "session",
    surface: "two-identity",
    interface: "filesystem",
    expected: Outcome.CHANNEL_ABSENT,
    observe: observeSessionFile,
  },
  {
    scenario: PROXY,
    context: "http",
    surface: "two-identity",
    interface: "proxy",
    expected: Outcome.OPAQUE,
    observe: observeProxy,
  },
  /**
   * The DB-8 residual, measured, not claimed: the proxy's exact-value redaction
   * covers the raw, Basic and query forms; an upstream that reflects base64 or
   * hex copies hands them to the agent.
   */
  {
    scenario: ECHO_REDACTION,
    context: "http",
    surface: "two-identity",
    interface: "proxy",
    expected: Outcome.BYPASSED,
    observe: observeProxyEchoRedaction,
  },
  {
    scenario: AGENT_SOCKET,
    context: "ssh",
    surface: "two-identity",
    interface: "ssh_agent",
    expected: Outcome.OPAQUE,
    observe: observeAgentSocket,
  },
  {
    scenario: ENVIRON,
    context: "process",
    surface: "two-identity",
    interface: "proxy+ssh_agent",
    expected: Outcome.HANDLE_ONLY,
    observe: observeEnviron,
  },
  /**
   * The container's view, not the boundary: the agent user is in the runner's
   * `docker` group, which is root-equivalent there, so the row measures the
   * container's configuration and what `docker inspect` shows of it.
   */
  {
    scenario: DOCKER,
    context: "docker",
    surface: "two-identity",
    interface: "proxy",
    expected: Outcome.HANDLE_ONLY,
    needs: "docker",
    observe: observeDocker,
  },
  {
    scenario: NEGATIVE,
    context: "process",
    surface: "engine",
    interface: "engine",
    expected: Outcome.LEAKED,
    observe: observeNegativeControl,
  },
];
