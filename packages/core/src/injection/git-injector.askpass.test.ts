import { spawnSync } from "node:child_process";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { InjectionPolicy } from "@harpoc/shared";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { GitInjector } from "./git-injector.js";
import { spawnCaptured } from "./spawn-captured.js";
import type { SpawnCapturedResult } from "./spawn-captured.js";
import { system32Path } from "../win32-paths.js";

vi.mock("./spawn-captured.js", () => ({ spawnCaptured: vi.fn() }));
// allowed.example resolves nowhere; the partial mock lets it past the DNS step of
// validateUrl so the repository URL can carry the ports these cases turn on.
vi.mock("./url-validator.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./url-validator.js")>();
  return {
    ...actual,
    validateUrl: vi.fn(async (urlStr: string) => {
      const url = new URL(urlStr);
      if (url.hostname === "allowed.example") {
        return { url, resolvedAddresses: ["203.0.113.10"] };
      }
      return actual.validateUrl(urlStr);
    }),
  };
});

const GIT = resolveExecutable("git", controlledPathDirs());

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

const REFUSAL = "harpoc: refusing to supply the credential for an unexpected host\n";

function policy(url: string): InjectionPolicy {
  return {
    url_allowlist: [url],
    command_allowlist: [GIT as string],
    env_allowlist: [],
    host_allowlist: [],
    response_mode: "filtered",
    response_header_allowlist: [],
    network_isolation: false,
    fs_isolation: false,
    smtp_recipient_allowlist: [],
    imap_read_only: false,
    strict_tree_exit: false,
  };
}

interface AskpassRun {
  stdout: string;
  stderr: string;
  status: number;
}

/** Run the written launcher as git does: one argument, the prompt. */
function runLauncher(env: Record<string, string>, prompt: string): AskpassRun {
  const launcher = env.GIT_ASKPASS as string;
  const r =
    process.platform === "win32"
      ? spawnSync(system32Path("cmd.exe"), ["/d", "/s", "/c", `""${launcher}" "${prompt}""`], {
          env,
          encoding: "utf8",
          windowsVerbatimArguments: true,
        })
      : spawnSync(launcher, [prompt], { env, encoding: "utf8" });
  return { stdout: r.stdout ?? "", stderr: r.stderr ?? "", status: r.status ?? -1 };
}

// TC-20: the askpass helper binds the credential to the validated origin — scheme,
// host and port — not the hostname alone: another port or scheme on the validated
// host is another service.
describe.skipIf(GIT === null)("GitInjector askpass binds the validated origin", () => {
  const injector = new GitInjector(null);
  const spawnMock = vi.mocked(spawnCaptured);

  beforeEach(() => {
    spawnMock.mockReset();
  });

  afterEach(() => {
    spawnMock.mockReset();
  });

  /** Clone `repository` and run every prompt through the launcher of its first credential-bearing step. */
  async function promptsFor(
    repository: string,
    allow: string,
    prompts: string[],
  ): Promise<{ origin: string | undefined; runs: AskpassRun[] }> {
    let origin: string | undefined;
    let runs: AskpassRun[] | undefined;
    spawnMock.mockImplementation((_cmd, _args, opts) => {
      const env = (opts as { env: Record<string, string> }).env;
      if (env.GIT_ASKPASS !== undefined && runs === undefined) {
        origin = env.HARPOC_GIT_ORIGIN;
        runs = prompts.map((p) => runLauncher(env, p));
      }
      return Promise.resolve(OK_RESULT);
    });
    await injector.executeWithSecret(
      { type: "git", operation: "clone", repository },
      new Uint8Array(Buffer.from("git-user:s3cret-token-value")),
      policy(allow),
      undefined,
    );
    expect(runs).toBeDefined();
    return { origin, runs: runs as AskpassRun[] };
  }

  it("refuses both prompts for another port on the validated host", async () => {
    const { origin, runs } = await promptsFor(
      "https://allowed.example:8443/org/r.git",
      "https://allowed.example:8443/*",
      [
        "Username for 'https://allowed.example:9443': ",
        "Password for 'https://u@allowed.example:9443': ",
      ],
    );
    expect(runs).toEqual([
      { stdout: "", stderr: REFUSAL, status: 1 },
      { stdout: "", stderr: REFUSAL, status: 1 },
    ]);
    expect(origin).toBe("https://allowed.example:8443");
  });

  it("answers both prompts for the validated port", async () => {
    const { runs } = await promptsFor(
      "https://allowed.example:8443/org/r.git",
      "https://allowed.example:8443/*",
      [
        "Username for 'https://allowed.example:8443': ",
        "Password for 'https://git-user@allowed.example:8443': ",
      ],
    );
    expect(runs.map((r) => [r.stdout.trim(), r.status])).toEqual([
      ["git-user", 0],
      ["s3cret-token-value", 0],
    ]);
  });

  it("treats the scheme's default port as the same port, written or omitted", async () => {
    const { origin, runs } = await promptsFor(
      "https://allowed.example/org/r.git",
      "https://allowed.example/*",
      [
        "Username for 'https://allowed.example': ",
        "Username for 'https://allowed.example:443': ",
        "Password for 'https://git-user@ALLOWED.example:443': ",
        "Username for 'https://allowed.example:8443': ",
      ],
    );
    expect(origin).toBe("https://allowed.example");
    expect(runs.map((r) => [r.stdout.trim(), r.status])).toEqual([
      ["git-user", 0],
      ["git-user", 0],
      ["s3cret-token-value", 0],
      ["", 1],
    ]);
  });

  it("refuses a prompt on another scheme for the validated host", async () => {
    const { runs } = await promptsFor(
      "https://allowed.example/org/r.git",
      "https://allowed.example/*",
      [
        "Username for 'http://allowed.example': ",
        "Password for 'http://git-user@allowed.example': ",
        "Password for 'http://git-user@allowed.example:443': ",
      ],
    );
    expect(runs).toEqual([
      { stdout: "", stderr: REFUSAL, status: 1 },
      { stdout: "", stderr: REFUSAL, status: 1 },
      { stdout: "", stderr: REFUSAL, status: 1 },
    ]);
  });

  it("carries the repository's explicit default port as the bare origin", async () => {
    const { origin, runs } = await promptsFor(
      "https://allowed.example:443/org/r.git",
      "https://allowed.example/*",
      ["Username for 'https://allowed.example': "],
    );
    expect(origin).toBe("https://allowed.example");
    expect(runs[0]?.stdout.trim()).toBe("git-user");
  });
});
