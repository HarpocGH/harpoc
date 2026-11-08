import { once } from "node:events";
import { userInfo } from "node:os";
import { describe, expect, it } from "vitest";
import { inventoryArgv } from "../assert/process-inventory-windows.js";
import {
  ERROR_LOGON_FAILURE,
  LAUNCH_FAILED_EXIT,
  LOGON_COMMAND_LINE_LIMIT,
  assertLauncherCommandLine,
  childEnvironment,
  launchFailure,
  launcherCommandLineLength,
  launcherSpec,
  runAsWindows,
  runLauncher,
  splitLauncherStderr,
  startAsWindows,
  systemPaths,
  windowsArgument,
  windowsCommandLine,
} from "./runas-windows.js";
import {
  AGENT_DRIVER_WINDOWS,
  EXISTS_PROBE,
  LIST_DIRECTORY,
  READ_FILE,
  REMOVE_FILE,
  REMOVE_TREE,
  REPORT_SELF,
  agentDriverArgv,
  cliArgv,
  daemonArgsWindows,
  forwardSlashes,
  nodeOneLiner,
  sshArgsWindows,
} from "./two-identity-windows.js";
import { TOKEN_FILE_REQUEST, WRITE_STDIN_TO_FILE } from "./two-identity.js";

const NODE = process.execPath;
const PRINT_ARGV_AND_ENV =
  "process.stdout.write(JSON.stringify({ argv: process.argv.slice(1), env: Object.keys(process.env) }))";
/** An account no host has: a refused logon counts toward no real account's lockout. */
const NO_ACCOUNT = { user: "harpoc-b7-no-such-account", password: "unit-fixture-pw-3" };
const LIMIT_REFUSAL =
  /^runAsWindows: the command line is \d+ characters, over the 1024 CreateProcessWithLogonW takes$/;

/** The e2e job's paths: setup-node's node on windows-latest, the checkout's built CLI, a run's root under the recipe's vault directory. */
const RUNNER_NODE = "C:\\hostedtoolcache\\windows\\node\\22.22.0\\x64\\node.exe";
const RUNNER_CLI = "D:\\a\\harpoc\\harpoc\\packages\\cli\\dist\\index.js";
const RUNNER_ROOT = "C:\\ProgramData\\harpoc\\vault\\harpoc-b7-x7JgEM";
const RUNNER_VAULT = `${RUNNER_ROOT}\\vault`;
const RUNNER_RUN = "C:\\ProgramData\\harpoc\\run";
const RUNNER_AGENT = "harpoc-ci-agent";
const RUNNER_PUBLIC = "C:\\ProgramData\\harpoc-b7-public\\harpoc-b7-agent-x7JgEM";

const onRunner = (argv: string[]): string[] => [RUNNER_NODE, ...argv.slice(1)];
const vaultCli = (args: string[]): string[] =>
  onRunner(cliArgv(RUNNER_CLI, ["--vault-dir", RUNNER_VAULT, ...args]));
const commandLineOf = (argv: string[]): number =>
  launcherCommandLineLength(launcherSpec(NO_ACCOUNT, argv));

describe("windowsArgument", () => {
  it.each([
    ["plain", "plain"],
    ["", '""'],
    ["two words", '"two words"'],
    ['say "hi"', '"say \\"hi\\""'],
    ["C:\\dir with space\\", '"C:\\dir with space\\\\"'],
    ['a\\\\"b', '"a\\\\\\\\\\"b"'],
    ["C:\\plain\\path", "C:\\plain\\path"],
    ["line1\nline2", '"line1\nline2"'],
  ])("quotes %j as %j", (arg, quoted) => {
    expect(windowsArgument(arg)).toBe(quoted);
  });

  it("joins a vector with single spaces", () => {
    expect(windowsCommandLine(["-e", "a b", "x"])).toBe('-e "a b" x');
  });
});

describe("childEnvironment", () => {
  const runner = {
    SystemRoot: "C:\\Windows",
    PATH: "C:\\Windows\\System32",
    HARPOC_TWO_USER_VAULT_PASSWORD: "runner-only-fixture-1",
    GITHUB_TOKEN: "runner-only-fixture-2",
    TEMP: "C:\\Users\\runneradmin\\AppData\\Local\\Temp",
  };

  it("carries the system's names and the account's own, never the runner's other variables", () => {
    const env = childEnvironment(
      "agent1",
      { HARPOC_PLACEHOLDER_API_KEY: "harpoc:api-key" },
      runner,
    );
    expect(env).toEqual({
      SystemRoot: "C:\\Windows",
      PATH: "C:\\Windows\\System32",
      USERNAME: "agent1",
      TEMP: "C:\\Windows\\Temp",
      TMP: "C:\\Windows\\Temp",
      HARPOC_PLACEHOLDER_API_KEY: "harpoc:api-key",
    });
    expect(Object.keys(env).some((name) => /PASSWORD|GITHUB/.test(name))).toBe(false);
  });

  it("matches the system's names case-insensitively and takes a given temporary directory", () => {
    const env = childEnvironment("agent1", {}, { SYSTEMROOT: "D:\\Win", path: "p" }, "D:\\t");
    expect(env["SystemRoot"]).toBe("D:\\Win");
    expect(env["PATH"]).toBe("p");
    expect(env["TEMP"]).toBe("D:\\t");
  });

  it("refuses a name that is not a variable name, naming the name and never the value", () => {
    expect(() => childEnvironment("agent1", { "BAD=NAME": "value-1" }, runner)).toThrow(
      /^childEnvironment: "BAD=NAME" is not a variable name$/,
    );
  });
});

describe("launcherSpec", () => {
  it("keeps the password in the spec alone — not in the arguments, the environment or the label", () => {
    const spec = launcherSpec(
      { user: "agent1", password: "pw-fixture-7f3a" },
      ["C:\\Windows\\System32\\curl.exe", "--version"],
      { env: { SSH_AUTH_SOCK: "\\\\.\\pipe\\harpoc-agent1-ssh-agent" }, stdin: "in" },
    );
    expect(spec.user).toBe("agent1");
    expect(spec.password).toBe("pw-fixture-7f3a");
    expect(spec.arguments).toBe("--version");
    expect(spec.stdin).toBe("in");
    expect(JSON.stringify({ ...spec, password: undefined }).includes("pw-fixture-7f3a")).toBe(
      false,
    );
  });

  it("refuses a relative command: the launcher resolves no PATH", () => {
    expect(() => launcherSpec({ user: "a", password: "p" }, ["node", "-v"])).toThrow(
      /argv\[0\] must be an absolute path/,
    );
  });
});

describe("the command line CreateProcessWithLogonW takes (lpCommandLine: at most 1024 characters)", () => {
  it("is FileName trimmed and quoted as .NET's Process.Start quotes it, then a space and Arguments when there are any", () => {
    expect(launcherCommandLineLength({ file: "C:\\x.exe", arguments: "" })).toBe(10);
    expect(launcherCommandLineLength({ file: "C:\\x.exe", arguments: "-v" })).toBe(13);
    expect(launcherCommandLineLength({ file: ' "C:\\x.exe" ', arguments: "-v" })).toBe(13);
    expect(
      launcherCommandLineLength(launcherSpec(NO_ACCOUNT, ["C:\\dir with space\\x.exe", "a b"])),
    ).toBe('"C:\\dir with space\\x.exe" "a b"'.length);
  });

  it("passes 1024 characters and refuses 1025, naming the length and the limit, never the command line", () => {
    const at = (total: number) => ({ file: "C:\\x.exe", arguments: "q".repeat(total - 11) });
    expect(LOGON_COMMAND_LINE_LIMIT).toBe(1024);
    expect(() => assertLauncherCommandLine(at(1024))).not.toThrow();
    let thrown: unknown;
    try {
      assertLauncherCommandLine(at(1025));
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(Error);
    expect((thrown as Error).message).toBe(
      "runAsWindows: the command line is 1025 characters, over the 1024 CreateProcessWithLogonW takes",
    );
  });

  it("runAsWindows and startAsWindows refuse an over-long command line before anything is spawned", async () => {
    const argv = [RUNNER_NODE, "-e", "q".repeat(1024)];
    await expect(runAsWindows(NO_ACCOUNT, argv)).rejects.toThrow(LIMIT_REFUSAL);
    let started: ReturnType<typeof startAsWindows> | undefined;
    let thrown: unknown;
    try {
      started = startAsWindows(NO_ACCOUNT, argv, { label: "an over-long command line" });
    } catch (err) {
      thrown = err;
    }
    if (started !== undefined && !started.exited()) await once(started.child, "close");
    expect(started).toBeUndefined();
    expect(thrown instanceof Error && LIMIT_REFUSAL.test(thrown.message)).toBe(true);
  });

  it("on the e2e job's paths the agent's driver as a node -e one-liner is over the limit, and every other command line the fixture passes is under it", () => {
    expect(commandLineOf(onRunner(nodeOneLiner(AGENT_DRIVER_WINDOWS)))).toBeGreaterThan(
      LOGON_COMMAND_LINE_LIMIT,
    );
    const knownHost = `[127.0.0.1]:65535 ssh-ed25519 ${"A".repeat(68)}`;
    const lines: Array<[string, string[]]> = [
      ...Object.entries({
        LIST_DIRECTORY,
        READ_FILE,
        EXISTS_PROBE,
        REMOVE_FILE,
        REMOVE_TREE,
        REPORT_SELF,
        TOKEN_FILE_REQUEST,
        WRITE_STDIN_TO_FILE,
      }).map(([name, script]): [string, string[]] => [
        name,
        onRunner(nodeOneLiner(script, `${RUNNER_ROOT}\\deploy-key.pem`)),
      ]),
      ["the agent's driver by its file", onRunner(agentDriverArgv(`${RUNNER_PUBLIC}\\driver.cjs`))],
      ["the teardown's process inventory", inventoryArgv("C:\\Windows")],
      ["stopAs's taskkill", [systemPaths("C:\\Windows").taskkill, "/pid", "123456", "/t", "/f"]],
      [
        "the pipe row's ssh",
        [
          systemPaths("C:\\Windows").ssh,
          ...sshArgsWindows({
            agentFiles: {
              knownHosts: forwardSlashes(`${RUNNER_PUBLIC}\\known_hosts`),
              identity: forwardSlashes(`${RUNNER_PUBLIC}\\identity.pub`),
            },
            sshServer: { port: 65535 },
          }),
        ],
      ],
      [
        "the daemon",
        onRunner(
          cliArgv(
            RUNNER_CLI,
            daemonArgsWindows(
              RUNNER_VAULT,
              RUNNER_RUN,
              RUNNER_AGENT,
              { rest: 65535, proxy: 65534 },
              `${RUNNER_ROOT}\\unlock.key.dpapi`,
            ),
          ),
        ),
      ],
      [
        "secret allow --url",
        vaultCli([
          "secret",
          "allow",
          "secret://api-key",
          "--url",
          "https://127.0.0.1:65535/*",
          "--proxy",
        ]),
      ],
      [
        "secret connection --http-ca",
        vaultCli([
          "secret",
          "connection",
          "secret://api-key",
          "--http-ca",
          "D:\\a\\harpoc\\harpoc\\packages\\e2e\\fixtures\\pki\\out\\ca.crt",
        ]),
      ],
      [
        "secret set --from-file",
        vaultCli(["secret", "set", "deploy-key", "--from-file", `${RUNNER_ROOT}\\deploy-key.pem`]),
      ],
      [
        "secret connection --known-host",
        vaultCli(["secret", "connection", "secret://deploy-key", "--known-host", knownHost]),
      ],
      [
        "policy grant",
        vaultCli([
          "policy",
          "grant",
          "secret://deploy-key",
          "--principal-type",
          "agent",
          "--principal-id",
          RUNNER_AGENT,
          "--permissions",
          "use",
        ]),
      ],
      [
        "auth token",
        vaultCli([
          "auth",
          "token",
          "--scope",
          "admin",
          "--principal-type",
          "user",
          "--label",
          "harpoc-b7 observer",
          "--ttl",
          "120",
          "--out",
          `${RUNNER_ROOT}\\admin.jwt`,
        ]),
      ],
      [
        "unlock-key enroll",
        vaultCli(["unlock-key", "enroll", "--out", `${RUNNER_ROOT}\\unlock.key.dpapi`, "--dpapi"]),
      ],
      [
        "proxy env",
        onRunner(
          cliArgv(RUNNER_CLI, [
            "proxy",
            "env",
            RUNNER_AGENT,
            "secret://api-key",
            "--runtime-dir",
            RUNNER_RUN,
            "--proxy-port",
            "65534",
            "--json",
          ]),
        ),
      ],
    ];
    for (const [name, argv] of lines) {
      expect(commandLineOf(argv), name).toBeLessThanOrEqual(LOGON_COMMAND_LINE_LIMIT);
    }
  });
});

describe("the launcher's stderr", () => {
  it("separates the pid line from the child's stderr", () => {
    expect(splitLauncherStderr("[runas] pid=4242\r\nboom\n")).toEqual({
      pid: 4242,
      stderr: "boom\n",
    });
    expect(splitLauncherStderr("boom\n")).toEqual({ pid: undefined, stderr: "boom\n" });
  });

  it("reads the Win32 error of a refused start, and nothing from any other run", () => {
    const refused = {
      code: LAUNCH_FAILED_EXIT,
      stdout: "",
      stderr: "[runas] start failed: native=1326 whatever the locale says\n",
    };
    expect(launchFailure(refused)).toBe(ERROR_LOGON_FAILURE);
    expect(launchFailure({ ...refused, code: 1 })).toBeUndefined();
  });

  it("reads a refused start's HRESULT-shaped error, the over-long command line's E_INVALIDARG", () => {
    expect(
      launchFailure({
        code: LAUNCH_FAILED_EXIT,
        stdout: "",
        stderr: "[runas] start failed: native=-2147024809 The parameter is incorrect\n",
      }),
    ).toBe(-2147024809);
  });

  it("pins the System32 paths to the given SystemRoot", () => {
    expect(systemPaths("C:\\Windows").powershell).toBe(
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    );
    expect(systemPaths("C:\\Windows").ssh).toBe("C:\\Windows\\System32\\OpenSSH\\ssh.exe");
    expect(systemPaths("C:\\Windows").icacls).toBe("C:\\Windows\\System32\\icacls.exe");
    expect(() => systemPaths("")).toThrow(/SystemRoot is not set/);
  });
});

/**
 * Windows only: the launcher is Windows PowerShell 5.1 and `ProcessStartInfo`'s
 * `UserName`; Linux has no `powershell.exe`. The cases run the launcher with no
 * account (the same-account seam) — the account switch itself needs a second
 * local account and is measured by `model-b-windows.e2e.test.ts` on the runner.
 */
describe.skipIf(process.platform !== "win32")("the launcher on Windows", () => {
  const spec = (args: string[], over: Record<string, unknown> = {}) => ({
    file: NODE,
    arguments: windowsCommandLine(args),
    env: childEnvironment(userInfo().username, { HARPOC_B7_ONLY: "given" }),
    stdin: "",
    ...over,
  });

  it("starts the command with exactly the arguments and environment it was given", async () => {
    process.env["HARPOC_B7_RUNNER_ONLY"] = "runner-fixture-1";
    try {
      const awkward = ["two words", 'say "hi"', "C:\\dir with space\\", "", "line1\nline2"];
      const run = await runLauncher(spec(["-e", PRINT_ARGV_AND_ENV, ...awkward]), {
        label: "argv",
      });
      expect(run.code).toBe(0);
      const seen = JSON.parse(run.stdout) as { argv: string[]; env: string[] };
      expect(seen.argv).toEqual(awkward);
      expect(seen.env).toContain("HARPOC_B7_ONLY");
      expect(seen.env).not.toContain("HARPOC_B7_RUNNER_ONLY");
    } finally {
      delete process.env["HARPOC_B7_RUNNER_ONLY"];
    }
  });

  it("forwards stdin, relays stdout, stderr and the exit code, and strips its own pid line", async () => {
    const code =
      "process.stdin.on('data', (d) => process.stdout.write(String(d).toUpperCase()));" +
      "process.stdin.on('end', () => { process.stderr.write('oops'); process.exit(7); });";
    const run = await runLauncher(spec(["-e", code], { stdin: "hello" }), { label: "stdin" });
    expect(run).toEqual({ code: 7, stdout: "HELLO", stderr: "oops" });
  });

  it("refuses an account it cannot log on (an unknown name: a real account would count a failed logon toward its lockout), starts nothing, and reports the Win32 error", async () => {
    const run = await runAsWindows(
      { user: "harpoc-b7-no-such-account", password: "wrong-password-fixture-1" },
      [NODE, "-e", "process.stdout.write('ran')"],
    );
    expect(run.code).toBe(LAUNCH_FAILED_EXIT);
    expect(run.stdout).toBe("");
    expect(launchFailure(run)).toBe(ERROR_LOGON_FAILURE);
    expect(run.stderr.includes("wrong-password-fixture-1")).toBe(false);
  }, 60_000);

  it("the system's bound is LOGON_COMMAND_LINE_LIMIT: with an account it cannot log on, 1024 characters reach the logon (ERROR_LOGON_FAILURE) and 1025 are refused E_INVALIDARG before it", async () => {
    const at = (total: number) => {
      const bare = launcherSpec(NO_ACCOUNT, [NODE]);
      return { ...bare, arguments: "q".repeat(total - launcherCommandLineLength(bare) - 1) };
    };
    const fits = at(LOGON_COMMAND_LINE_LIMIT);
    const over = at(LOGON_COMMAND_LINE_LIMIT + 1);
    expect([launcherCommandLineLength(fits), launcherCommandLineLength(over)]).toEqual([
      1024, 1025,
    ]);
    expect(launchFailure(await runLauncher(fits, { label: "1024 characters" }))).toBe(
      ERROR_LOGON_FAILURE,
    );
    expect(launchFailure(await runLauncher(over, { label: "1025 characters" }))).toBe(-2147024809);
  }, 60_000);
});
