import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import type { IncomingHttpHeaders } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { controlledPathDirs, resolveExecutable } from "@harpoc/core";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { GIT_SMART_HTTPS_CA_PEM, startGitSmartHttps } from "./helpers/git-smart-http.js";
import type { GitSmartHttps, SeenRequest } from "./helpers/git-smart-http.js";
import { tierRequired } from "./helpers/platform-tiers.js";
import {
  RAW_GET_TIMEOUT_MS,
  runCli,
  runCommand,
  startCliServerOnFreePort,
} from "./helpers/spawn-cli.js";
import type { CliServer } from "./helpers/spawn-cli.js";

/**
 * The egress credential proxy end to end (design M4 (i), tranche B2): the built
 * CLI's `server start --proxy` on a real vault, and a real `git` and `curl` that
 * hold only a placeholder and a use-only token, through the proxy's loopback TCP
 * listener to a smart-HTTP git server behind TLS. git reaches the proxy as its
 * remote through `url.<proxy>/<host>/.insteadOf` — plain HTTP to the proxy, the
 * proxy opens the TLS connection — with the placeholder as the Basic password
 * and the token in a URL-scoped `http.extraHeader`; both ride the environment
 * (`GIT_CONFIG_COUNT`), never argv, and curl reads its proxy header from stdin.
 * git first probes without a credential (a pass-through the fixture answers
 * 401), then sends the placeholder; only the requests carrying it are brokered
 * and audited. The two-UID exposure rows through the proxy are B6's.
 */

const GIT = resolveExecutable("git", controlledPathDirs());
const CURL = resolveExecutable("curl", controlledPathDirs());
const PASSWORD = "egress-proxy-master-pw-1";
const ARGON2_TIMEOUT_MS = 110_000;
const AGENT = "agent-p";
const USER = "vaultuser";
// The fixture password — a fixture literal, the credential the vault holds.
const VALUE = "egress-fixture-pw-7c1d";
const PLACEHOLDER = "harpoc:git-cred";
const PROXY_READY = /\[harpoc\] egress proxy listening on http:\/\/127\.0\.0\.1:(\d+)/;
// Repetitive, so git's zlib deflates it and no literal byte run of the value
// reaches the pack the proxy streams.
const SEED_README = `the fixture password is ${VALUE}\n`.repeat(16);
const GIT_TRACE_VARIABLES = new Set(["GIT_TRACE", "GIT_TRACE_CURL", "GIT_CURL_VERBOSE"]);

interface AuditRow {
  event_type: string;
  secret_id: string | null;
  principal_id: string | null;
  ip_address: string | null;
  success: boolean;
  detail: Record<string, unknown> | null;
}

/**
 * node:http GET with a socket deadline: fetch cannot observe the proxy's 407 —
 * the Fetch standard turns a 407 into a network error ("fetch failed").
 */
function rawGet(
  port: number,
  path: string,
  headers: Record<string, string>,
  timeoutMs = RAW_GET_TIMEOUT_MS,
): Promise<{ status: number; headers: IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
      let data = "";
      res.on("data", (chunk: Buffer) => (data += chunk.toString("utf8")));
      res.on("end", () =>
        resolve({ status: res.statusCode ?? 0, headers: res.headers, body: data }),
      );
    });
    req.on("error", reject);
    req.setTimeout(timeoutMs, () => {
      req.destroy(
        new Error(`rawGet ${path} on port ${String(port)} timed out after ${String(timeoutMs)} ms`),
      );
    });
    req.end();
  });
}

// A leg that exports the ssh-live tier ships git as well (TM-11): where git does not resolve
// on such a leg, this guard fails the file instead of letting the suite below skip silently.
it("ssh-live tier: required legs fail instead of skipping when git is unresolvable", () => {
  if (GIT === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no git resolves',
    );
  }
});

// Skipped where git does not resolve; the proxy's TCP listener runs on every platform.
describe.skipIf(GIT === null)(
  "egress proxy, rewrite mode, end to end (built CLI, real git)",
  () => {
    let root = "";
    let vaultDir = "";
    let srv = "";
    let fixture: GitSmartHttps | undefined;
    let daemon: CliServer | undefined;
    let proxyPort = 0;
    let useToken = "";
    let checkout = "";
    const outputs: string[] = [];

    const fixtureHost = (): string => `127.0.0.1:${String(fixture?.port)}`;
    const proxyBase = (): string => `http://127.0.0.1:${String(proxyPort)}`;
    const realBasic = `Basic ${Buffer.from(`${USER}:${VALUE}`).toString("base64")}`;
    const brokered = (): SeenRequest[] =>
      (fixture?.requests ?? []).filter((r) => r.headers.authorization === realBasic);

    function baseGitEnv(): NodeJS.ProcessEnv {
      // A host's git trace variables would print the request headers, the token's among them.
      const inherited = Object.fromEntries(
        Object.entries(process.env).filter(
          ([name]) => !GIT_TRACE_VARIABLES.has(name.toUpperCase()),
        ),
      );
      return {
        ...inherited,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: join(root, "empty.gitconfig"),
        GIT_TERMINAL_PROMPT: "0",
        GIT_AUTHOR_NAME: "harpoc-test",
        GIT_AUTHOR_EMAIL: "test@example.com",
        GIT_COMMITTER_NAME: "harpoc-test",
        GIT_COMMITTER_EMAIL: "test@example.com",
      };
    }

    /** The consumer's git configuration, in the environment: the rewrite and the token header. */
    function proxiedGitEnv(): NodeJS.ProcessEnv {
      return {
        ...baseGitEnv(),
        GIT_CONFIG_COUNT: "2",
        GIT_CONFIG_KEY_0: `url.http://${USER}:${PLACEHOLDER}@127.0.0.1:${String(proxyPort)}/${fixtureHost()}/.insteadOf`,
        GIT_CONFIG_VALUE_0: `https://${fixtureHost()}/`,
        GIT_CONFIG_KEY_1: `http.${proxyBase()}/.extraHeader`,
        GIT_CONFIG_VALUE_1: `Proxy-Authorization: Bearer ${useToken}`,
      };
    }

    async function git(cwd: string, args: string[], env = baseGitEnv()): Promise<string> {
      const run = await runCommand(GIT as string, args, { cwd, env });
      outputs.push(run.stdout, run.stderr);
      expect(run.code, `git ${args.join(" ")}: ${run.stderr}`).toBe(0);
      return run.stdout;
    }

    async function cli(args: string[], stdin?: string, timeoutMs?: number): Promise<string> {
      const run = await runCli(args, { vaultDir, stdin, timeoutMs });
      outputs.push(run.stdout, run.stderr);
      expect(run.code, `${args.join(" ")}: ${run.stderr}`).toBe(0);
      return run.stdout;
    }

    async function auditRows(event: string): Promise<AuditRow[]> {
      return JSON.parse(
        await cli(["audit", "--event", event, "--limit", "500", "--json"]),
      ) as AuditRow[];
    }

    beforeAll(async () => {
      root = mkdtempSync(join(tmpdir(), "harpoc-egress-proxy-"));
      vaultDir = join(root, "vault");
      srv = join(root, "srv");
      mkdirSync(vaultDir);
      mkdirSync(srv);
      writeFileSync(join(root, "empty.gitconfig"), "");
      const caFile = join(root, "fixture-ca.pem");
      writeFileSync(caFile, GIT_SMART_HTTPS_CA_PEM);

      const seed = join(root, "seed");
      await git(root, ["init", "-q", "-b", "main", seed]);
      writeFileSync(join(seed, "README.md"), SEED_README);
      await git(seed, ["add", "README.md"]);
      await git(seed, ["commit", "-q", "-m", "seed"]);
      await git(srv, ["clone", "-q", "--bare", seed, "repo.git"]);
      // A ref named after the value: the uncompressed ref advertisement carries it literally.
      await git(srv, ["clone", "-q", "--bare", seed, "leaky.git"]);
      // Its argv carries the value, so its failure is asserted as a boolean, never echoed.
      const branched = await runCommand(GIT as string, ["branch", VALUE, "main"], {
        cwd: join(srv, "leaky.git"),
        env: baseGitEnv(),
      });
      outputs.push(branched.stdout, branched.stderr);
      expect(branched.code === 0).toBe(true);
      fixture = await startGitSmartHttps({
        git: GIT as string,
        projectRoot: srv,
        user: USER,
        token: VALUE,
        env: baseGitEnv(),
      });

      // init leaves the vault unlocked with a session file; no unlock follows.
      await cli(["init"], `${PASSWORD}\n${PASSWORD}\n`, ARGON2_TIMEOUT_MS);
      await cli(["agent", "register", AGENT]);
      await cli(["secret", "set", "git-cred"], `${VALUE}\n`);
      await cli([
        "secret",
        "allow",
        "secret://git-cred",
        "--url",
        `https://${fixtureHost()}/*`,
        "--proxy",
      ]);
      await cli(["secret", "connection", "secret://git-cred", "--http-ca", caFile]);
      await cli([
        "policy",
        "grant",
        "secret://git-cred",
        "--principal-type",
        "agent",
        "--principal-id",
        AGENT,
        "--permissions",
        "use",
      ]);
      // Minted into a file as the deployment recipe does — the token never reaches a stdout.
      const tokenFile = join(root, "token.jwt");
      await cli([
        "auth",
        "token",
        "--agent",
        AGENT,
        "--scope",
        "use",
        "--ttl",
        "60",
        "--out",
        tokenFile,
      ]);
      useToken = readFileSync(tokenFile, "utf8").trim();

      // A pass-through (git's credential-less probe) carries no CA pin, so the daemon trusts the
      // fixture's CA by default, as it trusts a public upstream's. --proxy runs in the memory
      // session (B5): the daemon loads the session init wrote once and leaves it to the CLI below.
      const started = await startCliServerOnFreePort(
        (port) => [
          "server",
          "start",
          "--proxy",
          "--proxy-port",
          String(port),
          "--session",
          "memory",
        ],
        {
          vaultDir,
          env: { ...process.env, NODE_EXTRA_CA_CERTS: caFile },
          ready: (server) => server.waitForStderr(PROXY_READY),
        },
      );
      daemon = started.server;
      proxyPort = started.port;
    }, 180_000);

    afterAll(async () => {
      try {
        await daemon?.stop();
      } finally {
        try {
          await fixture?.close();
        } finally {
          if (root !== "") {
            rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
          }
        }
      }
    });

    it("git clone through the proxy: the fixture receives the real credential and never the placeholder or the token", async () => {
      checkout = join(root, "clone");
      await git(
        root,
        ["clone", "-q", `https://${fixtureHost()}/repo.git`, checkout],
        proxiedGitEnv(),
      );
      // DB-8's blind spot, pinned: the value inside git's zlib-compressed pack is no
      // literal byte run the redactor can match, so the checkout holds it.
      expect(readFileSync(join(checkout, "README.md"), "utf8") === SEED_README).toBe(true);
      expect((await git(checkout, ["config", "remote.origin.url"])).trim()).toBe(
        `https://${fixtureHost()}/repo.git`,
      );

      const seen = fixture?.requests ?? [];
      expect(seen.length).toBeGreaterThan(0);
      for (const r of seen) {
        const sent = JSON.stringify(r.headers);
        expect(r.headers["proxy-authorization"] === undefined).toBe(true);
        expect(sent.includes("harpoc:") || sent.includes(useToken)).toBe(false);
        expect([undefined, realBasic].includes(r.headers.authorization)).toBe(true);
      }
      // git's first request carries no credential — a pass-through, untouched.
      expect(seen[0]?.headers.authorization === undefined).toBe(true);
      expect(seen[0]?.headers["accept-encoding"]).not.toBe("identity");
      expect(brokered().length).toBeGreaterThan(0);
      for (const r of brokered()) expect(r.headers["accept-encoding"]).toBe("identity");
    }, 60_000);

    it("git push through the proxy lands the commit in the fixture's repository", async () => {
      writeFileSync(join(checkout, "pushed.txt"), "pushed through the egress proxy\n");
      await git(checkout, ["add", "pushed.txt"]);
      await git(checkout, ["commit", "-q", "-m", "through the proxy"]);
      await git(checkout, ["push", "-q", "origin", "main"], proxiedGitEnv());
      const tip = await git(join(srv, "repo.git"), ["log", "-1", "--format=%s", "main"]);
      expect(tip.trim()).toBe("through the proxy");
      expect(
        brokered().some(
          (r) => r.method === "POST" && r.url.startsWith("/repo.git/git-receive-pack"),
        ),
      ).toBe(true);
    }, 60_000);

    it.skipIf(CURL === null)(
      "curl's base-URL form: the placeholder as the Basic password is brokered and the value in the response redacted (skipped where curl does not resolve)",
      async () => {
        const run = await runCommand(
          CURL as string,
          [
            "-sS",
            "-H",
            "@-",
            "-u",
            `${USER}:${PLACEHOLDER}`,
            `${proxyBase()}/${fixtureHost()}/leaky.git/info/refs?service=git-upload-pack`,
          ],
          { stdin: `Proxy-Authorization: Bearer ${useToken}\n` },
        );
        outputs.push(run.stdout, run.stderr);
        expect(run.code, run.stderr).toBe(0);
        expect(run.stdout.includes("refs/heads/[REDACTED]")).toBe(true);
        expect(run.stdout.includes(VALUE)).toBe(false);
        expect(brokered().at(-1)?.url).toBe("/leaky.git/info/refs?service=git-upload-pack");
      },
      60_000,
    );

    it("one secret.use row with context proxy per brokered request — method, origin and the path without its query — and none for git's credential-less probes", async () => {
      const rows = (await auditRows(AuditEventType.SECRET_USE)).filter(
        (r) => r.detail?.["context"] === "proxy" && r.success,
      );
      const describeRow = (r: AuditRow): string =>
        `${String(r.detail?.["method"])} ${String(r.detail?.["path"])}`;
      const describeSeen = (r: SeenRequest): string => `${r.method} ${r.url.split("?")[0]}`;
      expect(rows.map(describeRow).sort()).toEqual(brokered().map(describeSeen).sort());
      for (const row of rows) {
        expect(row.principal_id).toBe(AGENT);
        expect(row.secret_id).toEqual(expect.any(String));
        expect(row.ip_address).toBe("127.0.0.1");
        expect(row.detail).toMatchObject({
          origin: `https://${fixtureHost()}`,
          status: 200,
          ca_pinned: true,
          interface: "proxy",
        });
        expect(String(row.detail?.["path"])).not.toContain("?");
        // sanitized only where the redaction changed the response: curl's ref advertisement.
        expect(row.detail?.["sanitized"]).toBe(
          row.detail?.["path"] === "/leaky.git/info/refs" ? true : undefined,
        );
      }
    }, 60_000);

    it("a request without Proxy-Authorization is refused 407 and an invalid token 401, neither reaching the fixture", async () => {
      const before = fixture?.requests.length;
      const path = `/${fixtureHost()}/repo.git/info/refs?service=git-upload-pack`;
      const basic = `Basic ${Buffer.from(`${USER}:${PLACEHOLDER}`).toString("base64")}`;
      const missing = await rawGet(proxyPort, path, { authorization: basic });
      expect(missing.status).toBe(407);
      expect(missing.headers["proxy-authenticate"]).toBe('Bearer realm="harpoc"');
      const invalid = await rawGet(proxyPort, path, {
        authorization: basic,
        "proxy-authorization": "Bearer not-a-token",
      });
      expect(invalid.status).toBe(401);
      expect((JSON.parse(invalid.body) as { error: string }).error).toBe(ErrorCode.INVALID_TOKEN);
      expect(fixture?.requests.length).toBe(before);
    }, 60_000);

    it("a placeholder bound for an origin outside the allowlist is refused 403 before that origin is contacted, with a failed secret.use row naming the origin", async () => {
      // Port 1 accepts nothing: a contact attempt would surface as 502, not 403.
      const refused = await rawGet(proxyPort, "/127.0.0.1:1/repo.git/info/refs", {
        authorization: `Basic ${Buffer.from(`${USER}:${PLACEHOLDER}`).toString("base64")}`,
        "proxy-authorization": `Bearer ${useToken}`,
      });
      expect(refused.status).toBe(403);
      const body = refused.body;
      expect(body.includes(VALUE) || body.includes(useToken)).toBe(false);
      expect((JSON.parse(body) as { error: string }).error).toBe(ErrorCode.URL_NOT_ALLOWED);
      const failed = (await auditRows(AuditEventType.SECRET_USE)).filter(
        (r) => r.detail?.["context"] === "proxy" && !r.success,
      );
      expect(failed).toHaveLength(1);
      expect(failed[0]?.detail).toMatchObject({
        origin: "https://127.0.0.1:1",
        error: ErrorCode.URL_NOT_ALLOWED,
      });
    }, 60_000);

    it("neither the value nor the token reaches the daemon's output, the clients' output or the audit trail", async () => {
      const trail = await cli(["audit", "--limit", "500", "--json"]);
      const swept = [daemon?.stdoutSoFar() ?? "", daemon?.stderrSoFar() ?? "", trail, ...outputs];
      for (const text of swept) {
        expect(text.includes(VALUE)).toBe(false);
        expect(text.includes(useToken)).toBe(false);
      }
    }, 60_000);

    it("the proxy listener writes its server.start row with the bound port", async () => {
      const rows = (await auditRows(AuditEventType.SERVER_START)).filter(
        (r) => r.detail?.["transport"] === "proxy",
      );
      expect(rows).toHaveLength(1);
      expect(rows[0]?.success).toBe(true);
      expect(rows[0]?.detail).toMatchObject({ port: proxyPort, host: "127.0.0.1" });
    }, 60_000);

    // Windows has no SIGTERM: child.kill() terminates the process without running
    // its handler, so no server.stop row is written there.
    it.skipIf(process.platform === "win32")(
      "the daemon stops on SIGTERM and writes the proxy listener's server.stop row (POSIX: SIGTERM runs the handler)",
      async () => {
        const server = daemon as CliServer;
        await server.stop();
        expect(server.child.exitCode).toBe(0);
        const rows = (await auditRows(AuditEventType.SERVER_STOP)).filter(
          (r) => r.detail?.["transport"] === "proxy",
        );
        expect(rows).toHaveLength(1);
        expect(rows[0]?.detail).toMatchObject({ port: proxyPort, trigger: "SIGTERM" });
      },
      60_000,
    );
  },
);
