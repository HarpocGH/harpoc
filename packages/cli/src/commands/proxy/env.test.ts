import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn(),
}));

import { loadUnlockedEngine } from "../../utils/vault-loader.js";
import { registerProxyEnvCommand } from "./env.js";
import { buildCli, spyCli, type CliSpies } from "../../__fixtures__/cli-harness.js";

const run = buildCli(
  (program) => registerProxyEnvCommand(program.command("proxy")),
  ["proxy", "env"],
);

const RUN_DIR = join("/run", "harpoc");
const CONSUMER_DIR = join(RUN_DIR, "agent");

let spies: CliSpies;
const platform = process.platform;

/** The platform the action reads for the socket line, stubbed so every row runs on every leg. */
function stubPlatform(value: NodeJS.Platform): void {
  Object.defineProperty(process, "platform", { value, configurable: true });
}

beforeEach(() => {
  vi.clearAllMocks();
  spies = spyCli();
  stubPlatform("linux");
});

afterEach(() => {
  stubPlatform(platform);
  vi.unstubAllEnvs();
  spies.restore();
});

describe("proxy env — the consumer's environment block", () => {
  it("prints the proxy's address, the base-URL form, the consumer's two paths and the placeholder; opens no vault", async () => {
    await run(["agent", "secret://gh-pat", "--runtime-dir", RUN_DIR]);

    expect(spies.stdout()).toBe(
      [
        "HARPOC_PROXY_URL=http://127.0.0.1:3128",
        "HARPOC_PROXY_BASE=http://127.0.0.1:3128/",
        `HARPOC_PROXY_TOKEN_FILE=${join(CONSUMER_DIR, "token.jwt")}`,
        `HARPOC_PROXY_SOCKET=${join(CONSUMER_DIR, "proxy.sock")}`,
        "HARPOC_PLACEHOLDER_GH_PAT=harpoc:gh-pat",
      ].join("\n"),
    );
    expect(spies.stderr()).toBe("");
    expect(loadUnlockedEngine).not.toHaveBeenCalled();
    expect(spies.exitSpy).not.toHaveBeenCalled();
  });

  it("prints one placeholder per handle in argument order — harpoc://<project>/<name> for a project handle", async () => {
    await run(["agent", "secret://gh-pat", "secret://ci/deploy-key", "--runtime-dir", RUN_DIR]);

    expect(spies.stdout().split("\n").slice(4)).toEqual([
      "HARPOC_PLACEHOLDER_GH_PAT=harpoc:gh-pat",
      "HARPOC_PLACEHOLDER_CI_DEPLOY_KEY=harpoc://ci/deploy-key",
    ]);
  });

  it("without --runtime-dir omits the two paths and says so in a comment line", async () => {
    await run(["agent", "secret://gh-pat"]);

    expect(spies.stdout()).toBe(
      [
        "HARPOC_PROXY_URL=http://127.0.0.1:3128",
        "HARPOC_PROXY_BASE=http://127.0.0.1:3128/",
        "# no --runtime-dir: the HARPOC_PROXY_TOKEN_FILE and HARPOC_PROXY_SOCKET lines are omitted",
        "HARPOC_PLACEHOLDER_GH_PAT=harpoc:gh-pat",
      ].join("\n"),
    );
  });

  // The command runs in the consumer's context, where a unit's $RUNTIME_DIRECTORY is that
  // unit's own directory, not the daemon's: the path is taken from --runtime-dir alone.
  it("does not read an ambient RUNTIME_DIRECTORY", async () => {
    vi.stubEnv("RUNTIME_DIRECTORY", join("/run", "agent-unit"));

    await run(["agent", "secret://gh-pat"]);

    expect(spies.stdout()).not.toContain("agent-unit");
    expect(spies.stdout()).toContain("# no --runtime-dir");
  });

  it("--proxy-port names the daemon's port in both URLs", async () => {
    await run(["agent", "secret://gh-pat", "--proxy-port", "4000"]);

    expect(spies.stdout().split("\n").slice(0, 2)).toEqual([
      "HARPOC_PROXY_URL=http://127.0.0.1:4000",
      "HARPOC_PROXY_BASE=http://127.0.0.1:4000/",
    ]);
  });

  it("--json prints the same block as one object", async () => {
    await run(["agent", "secret://gh-pat", "--runtime-dir", RUN_DIR, "--json"]);

    expect(JSON.parse(spies.stdout())).toEqual({
      HARPOC_PROXY_URL: "http://127.0.0.1:3128",
      HARPOC_PROXY_BASE: "http://127.0.0.1:3128/",
      HARPOC_PROXY_TOKEN_FILE: join(CONSUMER_DIR, "token.jwt"),
      HARPOC_PROXY_SOCKET: join(CONSUMER_DIR, "proxy.sock"),
      HARPOC_PLACEHOLDER_GH_PAT: "harpoc:gh-pat",
    });
  });

  it("prints a handle named twice once", async () => {
    await run(["agent", "secret://gh-pat", "secret://gh-pat"]);

    expect(
      spies
        .stdout()
        .split("\n")
        .filter((line) => line.startsWith("HARPOC_PLACEHOLDER_")),
    ).toEqual(["HARPOC_PLACEHOLDER_GH_PAT=harpoc:gh-pat"]);
  });
});

// B7 (DB-14, RP-B7-4): on Windows the proxy is the loopback TCP listener alone — no proxy.sock.
describe("proxy env on Windows (the platform stubbed)", () => {
  beforeEach(() => stubPlatform("win32"));

  it("prints the token file and, in place of the socket line, one # line", async () => {
    await run(["agent", "secret://gh-pat", "--runtime-dir", RUN_DIR]);

    expect(spies.stdout()).toBe(
      [
        "HARPOC_PROXY_URL=http://127.0.0.1:3128",
        "HARPOC_PROXY_BASE=http://127.0.0.1:3128/",
        `HARPOC_PROXY_TOKEN_FILE=${join(CONSUMER_DIR, "token.jwt")}`,
        "# Windows: the proxy serves no socket — the HARPOC_PROXY_SOCKET line is omitted (the TCP listener with the token file's token)",
        "HARPOC_PLACEHOLDER_GH_PAT=harpoc:gh-pat",
      ].join("\n"),
    );
  });

  it("--json carries no HARPOC_PROXY_SOCKET key", async () => {
    await run(["agent", "secret://gh-pat", "--runtime-dir", RUN_DIR, "--json"]);

    expect(JSON.parse(spies.stdout())).toEqual({
      HARPOC_PROXY_URL: "http://127.0.0.1:3128",
      HARPOC_PROXY_BASE: "http://127.0.0.1:3128/",
      HARPOC_PROXY_TOKEN_FILE: join(CONSUMER_DIR, "token.jwt"),
      HARPOC_PLACEHOLDER_GH_PAT: "harpoc:gh-pat",
    });
  });

  it("without --runtime-dir prints the same # line as on POSIX", async () => {
    await run(["agent", "secret://gh-pat"]);

    expect(spies.stdout().split("\n")[2]).toBe(
      "# no --runtime-dir: the HARPOC_PROXY_TOKEN_FILE and HARPOC_PROXY_SOCKET lines are omitted",
    );
  });
});

describe("proxy env — refusals, before anything is printed", () => {
  it.each([
    {
      label: "a consumer that is not a consumer name",
      argv: ["Alice", "secret://gh-pat"],
      line: 'Error: [INVALID_INPUT] consumer "Alice": not a directory name (lowercase letters, digits, _ and -, not starting with -; at most 255)',
    },
    {
      label: "a handle without the secret:// prefix",
      argv: ["agent", "gh-pat"],
      line: "Error: [INVALID_HANDLE] Invalid handle: gh-pat",
    },
    {
      label: "a --proxy-port out of range",
      argv: ["agent", "secret://gh-pat", "--proxy-port", "70000"],
      line: 'Error: [INVALID_INPUT] Invalid proxy port "70000". Must be 1-65535.',
    },
    {
      label: "a flag taken as the --runtime-dir path",
      argv: ["agent", "secret://gh-pat", "--runtime-dir", "--json"],
      line: "Error: [INVALID_INPUT] --runtime-dir: a flag, not a path (give a path that starts with a dash as ./-name)",
    },
    {
      label: "two handles that would share one variable",
      argv: ["agent", "secret://gh-pat", "secret://gh_pat"],
      line: "Error: [INVALID_INPUT] HARPOC_PLACEHOLDER_GH_PAT would name both harpoc:gh-pat and harpoc:gh_pat; print the two handles in separate calls",
    },
  ])("refuses $label", async ({ argv, line }) => {
    await expect(run(argv)).rejects.toThrow("process.exit");

    expect(spies.exitSpy).toHaveBeenCalledWith(1);
    expect(spies.errorSpy.mock.calls).toEqual([[line]]);
    expect(spies.logSpy).not.toHaveBeenCalled();
  });

  it("renders a refusal through the --json envelope", async () => {
    await expect(run(["Alice", "secret://gh-pat", "--json"])).rejects.toThrow("process.exit");

    expect(JSON.parse(spies.stderr())).toEqual({
      error: "INVALID_INPUT",
      message:
        'consumer "Alice": not a directory name (lowercase letters, digits, _ and -, not starting with -; at most 255)',
    });
    expect(spies.logSpy).not.toHaveBeenCalled();
  });
});
