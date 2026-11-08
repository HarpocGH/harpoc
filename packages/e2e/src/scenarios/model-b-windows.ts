import { spawn } from "node:child_process";
import { win32 } from "node:path";
import { AuditEventType, ErrorCode, SESSION_FILE_NAME, VAULT_DB_NAME } from "@harpoc/shared";
import {
  B7_MARKER,
  inventoryRecordText,
  judgeInventory,
  listAccountProcesses,
} from "../assert/process-inventory-windows.js";
import { SWEEP_RECORD_VARIABLE } from "../assert/proc-sweep.js";
import { systemPaths } from "../harness/runas-windows.js";
import { SSH2_EXEC_REPLY } from "../harness/ssh2-server.js";
import { runCommand } from "../harness/sudo.js";
import {
  LIST_DIRECTORY,
  READ_FILE,
  REPORT_SELF,
  curlArgsWindows,
  nodeOneLiner,
  sshArgsWindows,
} from "../harness/two-identity-windows.js";
import type { TwoAccountDeployment } from "../harness/two-identity-windows.js";
import type { TwoIdentityDeployment } from "../harness/two-identity.js";
import { Outcome } from "./scenario.js";
import type { OutcomeValue } from "./scenario.js";
import {
  asOutcome,
  captureCalls,
  newRows,
  requireProofs,
  sighted,
  unlockedHealth,
  untilArrived,
} from "./model-b.js";
import type { CallCapture } from "./model-b.js";

export { captureCalls };

/** The negative control's marker credential, placed in a child's argument by the harness itself. */
export const NEGATIVE_CONTROL_VALUE_WINDOWS = "b7-negative-control-value-9c3d";

const REDACTED = "[REDACTED]";
/** How much of ssh's stderr the pipe row's diagnostic carries, taken from the call its capture recorded (redacted with the capture's needles). */
const SSH_STDERR_TAIL_LINES = 20;
const HEADLESS = "b-win-headless-dpapi";
const VALUE_ROUTE = "b-win-two-account-value-route";
const VAULT_DIR = "b-win-two-account-vault-dir";
const PIPE = "b-win-agent-pipe-exposure";
const CMDLINE = "b-win-two-account-cmdline";
const NEGATIVE = "b-win-negative-same-account";

/**
 * One Windows model-B row: a Harpoc arm with no variant, as `ModelBScenario`;
 * `surface` is `two-account` for the rows on the two-account deployment and
 * `process` for the control, which needs no deployment.
 */
export interface ModelBWindowsScenario {
  scenario: string;
  context: string;
  surface: "two-account" | "process";
  interface: string;
  expected: OutcomeValue;
  observe(deployment: TwoAccountDeployment, capture: CallCapture): Promise<OutcomeValue>;
}

function proxyBase(d: Pick<TwoAccountDeployment, "agentEnv">): string {
  const base = d.agentEnv["HARPOC_PROXY_BASE"];
  if (base === undefined) throw new Error("harpoc proxy env printed no HARPOC_PROXY_BASE");
  return base;
}

async function observeHeadless(
  d: TwoAccountDeployment,
  capture: CallCapture,
): Promise<OutcomeValue> {
  const unlocked = await unlockedHealth(
    { restOrigin: d.restOrigin } as TwoIdentityDeployment,
    capture,
  );
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
  d: TwoAccountDeployment,
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

async function observeVaultDir(
  d: TwoAccountDeployment,
  capture: CallCapture,
): Promise<OutcomeValue> {
  const listing = await d.asVault(nodeOneLiner(LIST_DIRECTORY, d.vaultDir));
  capture.record(asOutcome(listing));
  const names = listing.stdout.split("\n").filter((name) => name !== "");
  const agentList = await d.asAgent(nodeOneLiner(LIST_DIRECTORY, d.vaultDir));
  capture.record(asOutcome(agentList));
  const agentRead = await d.asAgent(nodeOneLiner(READ_FILE, win32.join(d.vaultDir, VAULT_DB_NAME)));
  capture.record({
    ok: agentRead.code === 0,
    text: `bytes read: ${String(agentRead.stdout.length)}`,
    stderr: agentRead.stderr,
  });
  const unlocked = await unlockedHealth(
    { restOrigin: d.restOrigin } as TwoIdentityDeployment,
    capture,
  );
  if (agentRead.stdout.length > 0) return Outcome.LEAKED;
  if (agentList.code === 0) return Outcome.BYPASSED;
  if (names.includes(SESSION_FILE_NAME)) return Outcome.BLOCKED;
  requireProofs(VAULT_DIR, {
    vaultListed: listing.code === 0 && names.includes(VAULT_DB_NAME),
    daemonUnlocked: unlocked,
    agentRefused: /EPERM|EACCES/.test(agentList.stderr),
    readRefused: agentRead.code !== 0 && /EPERM|EACCES/.test(agentRead.stderr),
  });
  return Outcome.CHANNEL_ABSENT;
}

async function observePipe(d: TwoAccountDeployment, capture: CallCapture): Promise<OutcomeValue> {
  const before = await d.auditRows(AuditEventType.SECRET_USE);
  const seen = d.sshServer.events.length;
  const run = await d.asAgent([systemPaths().ssh, ...sshArgsWindows(d)], {
    env: { SSH_AUTH_SOCK: d.consumer.agentPipe },
    timeoutMs: 60_000,
  });
  const sshCall = capture.calls().length;
  capture.record(asOutcome(run));
  const rows = newRows(await d.auditRows(AuditEventType.SECRET_USE), before).filter(
    (row) => row.detail?.["context"] === "ssh_agent",
  );
  capture.record({ ok: true, text: JSON.stringify(rows) });
  if (sighted(d.credentials.all, run.stdout, run.stderr)) return Outcome.LEAKED;
  try {
    requireProofs(PIPE, {
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
  } catch (err) {
    const tail = (capture.calls()[sshCall]?.stderr ?? "").split(/\r?\n/);
    while (tail.length > 0 && tail[tail.length - 1] === "") tail.pop();
    throw new Error(
      `${(err as Error).message}; ssh exited ${String(run.code)}; the last ${String(SSH_STDERR_TAIL_LINES)} lines of its stderr, redacted as its record:\n${tail.slice(-SSH_STDERR_TAIL_LINES).join("\n")}`,
      { cause: err },
    );
  }
  return Outcome.OPAQUE;
}

async function observeInventory(
  d: TwoAccountDeployment,
  capture: CallCapture,
): Promise<OutcomeValue> {
  const daemonPid = d.daemon.pid();
  if (daemonPid === undefined) throw new Error("the daemon's pid is unknown");
  const judged = {
    credentials: d.credentials.all,
    placeholders: [d.placeholders.apiKey],
    foreignPids: [daemonPid],
  };
  const report = await d.asAgent(nodeOneLiner(REPORT_SELF), {
    env: d.agentEnv,
  });
  const own = JSON.parse(report.stdout) as { env: Record<string, string> };
  const ownLines = Object.entries(own.env)
    .map(([name, value]) => `${name}=${value}`)
    .filter((line) => SWEEP_RECORD_VARIABLE.test(line));
  capture.record({ ok: report.code === 0, text: ownLines.join("\n"), stderr: report.stderr });

  const echoHold = d.echo.hold();
  const sshHold = d.sshServer.hold();
  const tools = systemPaths();
  const driving = d.driveAgent([
    {
      command: tools.curl,
      args: curlArgsWindows(d, `${proxyBase(d)}127.0.0.1:${String(d.echo.port)}/echo/held`),
      proxyAuthorization: true,
    },
    { command: tools.ssh, args: sshArgsWindows(d) },
  ]);
  let entries: Awaited<ReturnType<typeof listAccountProcesses>>;
  try {
    await untilArrived(
      Promise.all([echoHold.arrived, sshHold.arrived]),
      driving,
      "the agent's curl and ssh",
    );
    entries = await listAccountProcesses((argv) => d.asAgent(argv));
  } finally {
    echoHold.release();
    sshHold.release();
    void driving.catch(() => undefined);
  }
  const results = await driving;
  const verdict = judgeInventory(entries, judged);
  for (const entry of entries) {
    const text = inventoryRecordText(entry, judged);
    if (text !== undefined) capture.record({ ok: true, text });
  }
  for (const result of results) capture.record(asOutcome(result));
  if (verdict.credentialSeen) return Outcome.LEAKED;
  if (sighted(d.credentials.all, report.stdout, ...results.flatMap((r) => [r.stdout, r.stderr]))) {
    return Outcome.LEAKED;
  }
  requireProofs(CMDLINE, {
    ownReportRead: report.code === 0,
    placeholderInOwnEnvironment: own.env["HARPOC_PLACEHOLDER_API_KEY"] === d.placeholders.apiKey,
    pipeInOwnEnvironment: own.env["SSH_AUTH_SOCK"] === d.consumer.agentPipe,
    tokenFileNamedNotRead: own.env["HARPOC_PROXY_TOKEN_FILE"] === d.consumer.tokenFile,
    runnerJobVariablesAbsent: !Object.keys(own.env).some((name) =>
      /^(HARPOC_TWO_USER_|GITHUB_|ACTIONS_)/.test(name),
    ),
    placeholderListed: verdict.placeholderSeen,
    curlListed: verdict.commands.includes("curl.exe"),
    sshListed: verdict.commands.includes("ssh.exe"),
    daemonListed: verdict.foreignListed.includes(daemonPid),
    toolsCompleted: results.length === 2 && results.every((r) => r.code === 0),
  });
  if (verdict.foreignReadable.length > 0) return Outcome.BYPASSED;
  return Outcome.HANDLE_ONLY;
}

async function observeNegativeControl(
  _d: TwoAccountDeployment,
  capture: CallCapture,
): Promise<OutcomeValue> {
  const child = spawn(
    process.execPath,
    ["-e", "setTimeout(() => {}, 60000)", `${B7_MARKER}-control`, NEGATIVE_CONTROL_VALUE_WINDOWS],
    { shell: false, stdio: "ignore", windowsHide: true },
  );
  const judged = {
    credentials: [NEGATIVE_CONTROL_VALUE_WINDOWS],
    placeholders: [],
    foreignPids: [],
  };
  try {
    const pid = child.pid;
    if (pid === undefined) throw new Error("the control's child has no pid");
    const entries = await listAccountProcesses((argv) =>
      runCommand(argv[0] ?? "", argv.slice(1), { label: "the control's process listing" }),
    );
    const mine = entries.filter((entry) => entry.pid === pid);
    if (mine.length !== 1) throw new Error("the control's child is not in the listing");
    for (const entry of mine) {
      const text = inventoryRecordText(entry, judged);
      if (text !== undefined) capture.record({ ok: true, text });
    }
    return judgeInventory(mine, judged).credentialSeen ? Outcome.LEAKED : Outcome.OPAQUE;
  } finally {
    child.kill();
  }
}

/**
 * The six Windows rows, in run order: the headless row first, so its
 * `use_secret` is the daemon's first; the control last, on the harness's own
 * child.
 */
export const MODEL_B_WINDOWS_SCENARIOS: ModelBWindowsScenario[] = [
  {
    scenario: HEADLESS,
    context: "http",
    surface: "two-account",
    interface: "rest",
    expected: Outcome.SUCCEEDED,
    observe: observeHeadless,
  },
  {
    scenario: VALUE_ROUTE,
    context: "rest",
    surface: "two-account",
    interface: "rest",
    expected: Outcome.BLOCKED,
    observe: observeValueRoute,
  },
  {
    scenario: VAULT_DIR,
    context: "session",
    surface: "two-account",
    interface: "filesystem",
    expected: Outcome.CHANNEL_ABSENT,
    observe: observeVaultDir,
  },
  {
    scenario: PIPE,
    context: "ssh",
    surface: "two-account",
    interface: "ssh_agent",
    expected: Outcome.OPAQUE,
    observe: observePipe,
  },
  /**
   * The measured residual, not a claim: the vault daemon's command line is
   * readable to the agent account through its own process listing and carries
   * no secret, since none is ever passed on a command line — so the row is
   * BYPASSED; a credential in any text the agent reads is LEAKED.
   */
  {
    scenario: CMDLINE,
    context: "process",
    surface: "two-account",
    interface: "proxy+ssh_agent",
    expected: Outcome.BYPASSED,
    observe: observeInventory,
  },
  {
    scenario: NEGATIVE,
    context: "process",
    surface: "process",
    interface: "process-inventory",
    expected: Outcome.LEAKED,
    observe: observeNegativeControl,
  },
];
