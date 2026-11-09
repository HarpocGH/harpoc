import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resolveCliEntry } from "./fixtures.js";
import { runCommand } from "./sudo.js";
import {
  AGENT_DRIVER,
  AGENT_ENV_NAMES,
  TOKEN_FILE_REQUEST,
  UNLOCK_CREDENTIAL_NAME,
  WRITE_STDIN_TO_FILE,
  agentEnvironment,
  consumerPaths,
  daemonArgs,
  issueTokenSpec,
} from "./two-identity.js";

describe("the two-identity deployment's argv and paths", () => {
  it("names the consumer directory's token file and sockets under the runtime directory", () => {
    expect(consumerPaths("/run/harpoc", "harpoc-ci-agent")).toEqual({
      dir: "/run/harpoc/harpoc-ci-agent",
      tokenFile: "/run/harpoc/harpoc-ci-agent/token.jwt",
      proxySocket: "/run/harpoc/harpoc-ci-agent/proxy.sock",
      agentSocket: "/run/harpoc/harpoc-ci-agent/ssh-agent.sock",
    });
  });

  it("mints the agent a use-only token for the two handles, in the --issue-token grammar", () => {
    expect(issueTokenSpec("agent", "/run/harpoc/agent/token.jwt", 60)).toBe(
      "agent=agent,file=/run/harpoc/agent/token.jwt,scope=use,secrets=api-key+deploy-key,ttl=60",
    );
  });

  it("starts the daemon headless in memory mode from the credential, with REST, the proxy, the socket and the token file", () => {
    expect(
      daemonArgs("/tmp/harpoc-b6-x/vault", "/run/harpoc", "agent", { rest: 41001, proxy: 41002 }),
    ).toEqual([
      "--vault-dir",
      "/tmp/harpoc-b6-x/vault",
      "server",
      "start",
      "--rest",
      "--port",
      "41001",
      "--runtime-dir",
      "/run/harpoc",
      "--session",
      "memory",
      "--unlock-credential",
      UNLOCK_CREDENTIAL_NAME,
      "--proxy",
      "--proxy-port",
      "41002",
      "--ssh-agent",
      "--issue-token",
      "agent=agent,file=/run/harpoc/agent/token.jwt,scope=use,secrets=api-key+deploy-key,ttl=60",
    ]);
  });
});

describe("the agent's environment from harpoc proxy env --json", () => {
  it("hands the agent the whole block the built CLI prints for it, the api key and a runtime directory", async () => {
    const run = await runCommand(
      process.execPath,
      [
        resolveCliEntry(),
        "proxy",
        "env",
        "agent",
        "secret://api-key",
        "--runtime-dir",
        "/run/harpoc",
        "--proxy-port",
        "41002",
        "--json",
      ],
      { label: "harpoc proxy env" },
    );
    expect(run.code, run.stderr).toBe(0);
    const printed = JSON.parse(run.stdout) as Record<string, string>;
    expect(agentEnvironment(printed, AGENT_ENV_NAMES)).toEqual(printed);
  });

  it("refuses a block carrying a variable off its list, naming each one and no value — whatever is handed on rides sudo's world-readable argv", () => {
    expect(() =>
      agentEnvironment(
        {
          HARPOC_PROXY_URL: "http://127.0.0.1:41002",
          HARPOC_PROXY_TOKEN: "off-list-value-1",
          HTTPS_PROXY: "off-list-value-2",
        },
        AGENT_ENV_NAMES,
      ),
    ).toThrow(/^harpoc proxy env printed unexpected variables: HARPOC_PROXY_TOKEN, HTTPS_PROXY$/);
  });
});

/**
 * The scripts the deployment runs as another user, run here as this one: the
 * token is read from its file by the script, never handed to it.
 */
describe("the two-identity deployment's user-side scripts", () => {
  let dir = "";
  const token = "fixture-token-b6-1";

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "harpoc-b6-scripts-"));
    writeFileSync(join(dir, "token.jwt"), `${token}\n`);
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("TOKEN_FILE_REQUEST sends the file's token as the bearer and prints the status and body", async () => {
    const seen: string[] = [];
    const server = createServer((req, res) => {
      seen.push(`${req.method ?? ""} ${req.url ?? ""} ${req.headers.authorization ?? ""}`);
      res.writeHead(403, { "content-type": "application/json" });
      res.end('{"error":"ACCESS_DENIED"}');
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const { port } = server.address() as AddressInfo;
      const run = await runCommand(process.execPath, ["-e", TOKEN_FILE_REQUEST], {
        stdin: JSON.stringify({
          url: `http://127.0.0.1:${String(port)}/api/v1/secrets/api-key/value`,
          method: "GET",
          tokenFile: join(dir, "token.jwt"),
        }),
        label: "token-file request",
      });
      expect(run.code, run.stderr).toBe(0);
      expect(JSON.parse(run.stdout)).toEqual({ status: 403, body: '{"error":"ACCESS_DENIED"}' });
      // Boolean-shaped: a failing comparison never echoes the token.
      expect(
        seen.length === 1 && seen[0] === `GET /api/v1/secrets/api-key/value Bearer ${token}`,
      ).toBe(true);
      expect(run.stdout.includes(token) || run.stderr.includes(token)).toBe(false);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("AGENT_DRIVER runs its commands without a shell, the proxy header built from the token file on the stdin of those that ask", async () => {
    const echoStdin = ["-e", "process.stdin.pipe(process.stdout)"];
    const run = await runCommand(process.execPath, ["-e", AGENT_DRIVER], {
      env: { ...process.env, HARPOC_PROXY_TOKEN_FILE: join(dir, "token.jwt") },
      stdin: JSON.stringify({
        commands: [
          { command: process.execPath, args: echoStdin, proxyAuthorization: true },
          { command: process.execPath, args: echoStdin },
          { command: process.execPath, args: ["-e", "process.exit(3)"] },
        ],
      }),
      label: "agent driver",
    });
    expect(run.code).toBe(0);
    const { results } = JSON.parse(run.stdout) as {
      results: Array<{ code: number | null; stdout: string; stderr: string }>;
    };
    expect(results.map((r) => r.code)).toEqual([0, 0, 3]);
    // Boolean-shaped: a failing comparison never echoes the token.
    expect(results[0]?.stdout === `Proxy-Authorization: Bearer ${token}\n`).toBe(true);
    expect(results.slice(1).every((r) => r.stdout === "" && r.stderr === "")).toBe(true);
  });

  it("WRITE_STDIN_TO_FILE writes stdin to a new file and refuses one that exists", async () => {
    const target = join(dir, "copied.pem");
    const first = await runCommand(process.execPath, ["-e", WRITE_STDIN_TO_FILE, target], {
      stdin: "-----BEGIN FIXTURE-----\n",
      label: "write stdin",
    });
    expect(first.code, first.stderr).toBe(0);
    expect(readFileSync(target, "utf8")).toBe("-----BEGIN FIXTURE-----\n");
    const second = await runCommand(process.execPath, ["-e", WRITE_STDIN_TO_FILE, target], {
      stdin: "replacement\n",
      label: "write stdin again",
    });
    expect(second.code).not.toBe(0);
    expect(readFileSync(target, "utf8")).toBe("-----BEGIN FIXTURE-----\n");
  });
});
