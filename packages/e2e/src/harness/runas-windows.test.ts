import { userInfo } from "node:os";
import { describe, expect, it } from "vitest";
import {
  ERROR_LOGON_FAILURE,
  LAUNCH_FAILED_EXIT,
  childEnvironment,
  launchFailure,
  launcherSpec,
  runAsWindows,
  runLauncher,
  splitLauncherStderr,
  systemPaths,
  windowsArgument,
  windowsCommandLine,
} from "./runas-windows.js";

const NODE = process.execPath;
const PRINT_ARGV_AND_ENV =
  "process.stdout.write(JSON.stringify({ argv: process.argv.slice(1), env: Object.keys(process.env) }))";

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
});
