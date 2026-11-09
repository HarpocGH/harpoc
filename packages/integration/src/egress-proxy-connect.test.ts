import { X509Certificate } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect as tlsConnect } from "node:tls";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { controlledPathDirs, resolveExecutable } from "@harpoc/core";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { GIT_SMART_HTTPS_CA_PEM, startGitSmartHttps } from "./helpers/git-smart-http.js";
import type { GitSmartHttps, SeenRequest } from "./helpers/git-smart-http.js";
import { canon } from "./helpers/key-needles.js";
import { tierRequired } from "./helpers/platform-tiers.js";
import {
  RAW_GET_TIMEOUT_MS,
  runCli,
  runCommand,
  startCliServerOnFreePort,
} from "./helpers/spawn-cli.js";
import type { CliServer } from "./helpers/spawn-cli.js";

/**
 * The egress proxy's CONNECT mode end to end (design M4 (ii), tranche B8): the
 * built CLI's `harpoc proxy ca init` / `export` and `server start --proxy` on a
 * real vault, and a real `curl` and `git` that hold only a placeholder and a
 * use-only token, tunnelling `https://127.0.0.1:<port>` through the proxy's
 * loopback listener to the TLS smart-HTTP fixture. The proxy terminates the
 * tunnel's TLS with a leaf for 127.0.0.1 and the intermediate that issued it
 * under the name-constrained Harpoc root — the root is what the clients trust,
 * swaps the placeholder and re-encrypts upstream to the fixture's pinned
 * certificate. The CONNECT target is the literal 127.0.0.1 (no name resolves);
 * the host outside the constraints is the loopback name `localhost`, refused
 * before any resolution or contact. curl takes the token on stdin
 * (`--proxy-header @-`); git takes it as the Basic password of `http.proxy`
 * through `GIT_CONFIG_COUNT`, never argv. The plain-HTTP rows are
 * `egress-proxy.test.ts`'s; this file holds the CONNECT ones.
 */

const GIT = resolveExecutable("git", controlledPathDirs());
const CURL = resolveExecutable("curl", controlledPathDirs());
const PASSWORD = "egress-connect-master-pw-1";
const ARGON2_TIMEOUT_MS = 110_000;
const AGENT = "agent-c";
const USER = "vaultuser";
// The fixture password — a fixture literal, the credential the vault holds.
const VALUE = "egress-connect-fixture-pw-3e9a";
const PLACEHOLDER = "harpoc:git-cred";
const CA_HOST = "127.0.0.1";
const OUTSIDE_HOST = "localhost";
const PROXY_READY = /\[harpoc\] egress proxy listening on http:\/\/127\.0\.0\.1:(\d+)/;
const CONNECT_READY =
  /\[harpoc\] egress proxy listening on http:\/\/127\.0\.0\.1:\d+.* — CONNECT for 1 host\(s\)/;
const SEED_README = `the fixture password is ${VALUE}\n`.repeat(16);
const GIT_TRACE_VARIABLES = new Set(["GIT_TRACE", "GIT_TRACE_CURL", "GIT_CURL_VERBOSE"]);
// An inherited proxy, bypass list or trust file would decide the rows instead of their own options.
const CLIENT_VARIABLES = new Set([
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "NO_PROXY",
  "CURL_CA_BUNDLE",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "GIT_SSL_CAINFO",
  "GIT_SSL_NO_VERIFY",
  "GIT_HTTP_PROXY_AUTHMETHOD",
]);
// Git for Windows honours GIT_SSL_CAINFO under Schannel only with these keys (core's WIN32_PINNED_CA_CONFIG).
const WIN32_GIT_TLS: Array<[string, string]> =
  process.platform === "win32"
    ? [
        ["http.sslBackend", "schannel"],
        ["http.schannelUseSSLCAInfo", "true"],
        ["http.schannelCheckRevoke", "best-effort"],
      ]
    : [];
// Schannel checks revocation, and the Harpoc CA publishes no distribution point.
const WIN32_CURL_TLS = process.platform === "win32" ? ["--ssl-revoke-best-effort"] : [];
// Every P-256 private key the CLI or the proxy could leak, whatever its value: the armour marker,
// the fixed head of its PKCS#8 and of its SEC1 DER in base64.
const PRIVATE_KEY_NEEDLES = [
  "PRIVATE KEY-----",
  "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg",
  "MHcCAQEEI",
];

interface AuditRow {
  event_type: string;
  secret_id: string | null;
  principal_id: string | null;
  ip_address: string | null;
  success: boolean;
  detail: Record<string, unknown> | null;
}

interface ConnectAnswer {
  status: number;
  headers: Record<string, string[]>;
  body: string;
}

/** A raw `CONNECT <authority>` with a socket deadline, read up to its head and body. */
function rawConnect(
  port: number,
  authority: string,
  headers: Record<string, string>,
  timeoutMs = RAW_GET_TIMEOUT_MS,
): Promise<ConnectAnswer> {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: "127.0.0.1", port });
    let data = Buffer.alloc(0);
    const timer = setTimeout(() => {
      socket.destroy(
        new Error(
          `rawConnect ${authority} on port ${String(port)} timed out after ${String(timeoutMs)} ms`,
        ),
      );
    }, timeoutMs);
    const lines = [
      `CONNECT ${authority} HTTP/1.1`,
      `Host: ${authority}`,
      ...Object.entries(headers).map(([name, value]) => `${name}: ${value}`),
    ];
    socket.on("connect", () => socket.write(`${lines.join("\r\n")}\r\n\r\n`));
    socket.on("data", (chunk: Buffer) => {
      data = Buffer.concat([data, chunk]);
      const end = data.indexOf("\r\n\r\n");
      if (end < 0) return;
      const head = data.subarray(0, end).toString("latin1").split("\r\n");
      const status = Number.parseInt((head[0] ?? "").split(" ")[1] ?? "0", 10);
      const parsed: Record<string, string[]> = {};
      for (const line of head.slice(1)) {
        const colon = line.indexOf(":");
        const name = line.slice(0, colon).trim().toLowerCase();
        (parsed[name] ??= []).push(line.slice(colon + 1).trim());
      }
      const length = Number.parseInt(parsed["content-length"]?.[0] ?? "0", 10);
      const body = data.subarray(end + 4);
      if (status !== 200 && body.length < length) return;
      clearTimeout(timer);
      socket.destroy();
      resolve({ status, headers: parsed, body: body.subarray(0, length).toString("utf8") });
    });
    socket.on("error", (err: Error) => {
      clearTimeout(timer);
      reject(err);
    });
    socket.on("close", () => {
      clearTimeout(timer);
      reject(new Error(`rawConnect ${authority}: the proxy closed before a complete answer`));
    });
  });
}

/**
 * The leaf the proxy presents inside an authenticated tunnel and the certificate that issued it,
 * the chain verified by Node's TLS against the root `ca`.
 */
function tunnelChain(
  port: number,
  authority: string,
  token: string,
  ca: string,
  timeoutMs = RAW_GET_TIMEOUT_MS,
): Promise<{ leaf: X509Certificate; issuer: X509Certificate }> {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: "127.0.0.1", port });
    const timer = setTimeout(() => {
      socket.destroy(new Error(`tunnelChain ${authority} timed out after ${String(timeoutMs)} ms`));
    }, timeoutMs);
    const fail = (err: Error): void => {
      clearTimeout(timer);
      socket.destroy();
      reject(err);
    };
    let head = Buffer.alloc(0);
    const onData = (chunk: Buffer): void => {
      head = Buffer.concat([head, chunk]);
      if (head.indexOf("\r\n\r\n") < 0) return;
      socket.off("data", onData);
      const statusLine = head.subarray(0, head.indexOf("\r\n")).toString("latin1");
      if (statusLine.split(" ")[1] !== "200") {
        fail(new Error(`CONNECT ${authority} answered ${statusLine}`));
        return;
      }
      const tls = tlsConnect({ socket, ca, host: authority.slice(0, authority.lastIndexOf(":")) });
      tls.on("error", fail);
      tls.on("secureConnect", () => {
        const presented = tls.getPeerCertificate(true);
        clearTimeout(timer);
        tls.destroy();
        resolve({
          leaf: new X509Certificate(presented.raw),
          issuer: new X509Certificate(presented.issuerCertificate.raw),
        });
      });
    };
    socket.on("connect", () =>
      socket.write(
        `CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\nProxy-Authorization: Bearer ${token}\r\n\r\n`,
      ),
    );
    socket.on("data", onData);
    socket.on("error", fail);
    socket.on("close", () =>
      fail(new Error(`tunnelChain ${authority}: the proxy closed before a complete answer`)),
    );
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

// Skipped where git does not resolve; the proxy's TCP listener and CONNECT run on every platform.
describe.skipIf(GIT === null)(
  "egress proxy, CONNECT mode, end to end (built CLI, the Harpoc CA, real git and curl)",
  () => {
    let root = "";
    let vaultDir = "";
    let srv = "";
    let runtimeDir = "";
    let fixtureCaFile = "";
    let fixture: GitSmartHttps | undefined;
    let useToken = "";
    const outputs: string[] = [];

    const fixturePort = (): string => String(fixture?.port);
    const fixtureHost = (): string => `${CA_HOST}:${fixturePort()}`;
    const realBasic = `Basic ${Buffer.from(`${USER}:${VALUE}`).toString("base64")}`;
    const brokered = (): SeenRequest[] =>
      (fixture?.requests ?? []).filter((r) => r.headers.authorization === realBasic);

    function inherited(): NodeJS.ProcessEnv {
      return Object.fromEntries(
        Object.entries(process.env).filter(
          ([name]) =>
            !GIT_TRACE_VARIABLES.has(name.toUpperCase()) &&
            !CLIENT_VARIABLES.has(name.toUpperCase()),
        ),
      );
    }

    function baseGitEnv(): NodeJS.ProcessEnv {
      return {
        ...inherited(),
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: join(root, "empty.gitconfig"),
        GIT_TERMINAL_PROMPT: "0",
        GIT_AUTHOR_NAME: "harpoc-test",
        GIT_AUTHOR_EMAIL: "test@example.com",
        GIT_COMMITTER_NAME: "harpoc-test",
        GIT_COMMITTER_EMAIL: "test@example.com",
      };
    }

    /**
     * The consumer's git configuration, in the environment: the proxy with the token as its
     * Basic password (git answers the proxy's 407 Basic challenge with it), the placeholder as
     * the remote's password through `insteadOf` (the origin URL keeps no placeholder), and the
     * Harpoc CA through `GIT_SSL_CAINFO`.
     */
    function connectGitEnv(proxyPort: number, caFile: string): NodeJS.ProcessEnv {
      const pairs: Array<[string, string]> = [
        ["http.proxy", `http://harpoc:${useToken}@127.0.0.1:${String(proxyPort)}`],
        [
          `url.https://${USER}:${PLACEHOLDER}@${fixtureHost()}/.insteadOf`,
          `https://${fixtureHost()}/`,
        ],
        ...WIN32_GIT_TLS,
      ];
      const env: NodeJS.ProcessEnv = {
        ...baseGitEnv(),
        GIT_SSL_CAINFO: caFile,
        GIT_CONFIG_COUNT: String(pairs.length),
      };
      pairs.forEach(([key, value], index) => {
        env[`GIT_CONFIG_KEY_${String(index)}`] = key;
        env[`GIT_CONFIG_VALUE_${String(index)}`] = value;
      });
      return env;
    }

    async function git(cwd: string, args: string[], env = baseGitEnv()): Promise<string> {
      const run = await runCommand(GIT as string, args, { cwd, env });
      outputs.push(run.stdout, run.stderr);
      expect(run.code, `git ${args.join(" ")}: ${run.stderr}`).toBe(0);
      return run.stdout;
    }

    /** curl with `-q` first (no `.curlrc`), the codes on the last line: `<http_code> <http_connect>`. */
    async function curl(
      args: string[],
      opts: { stdin?: string; env?: NodeJS.ProcessEnv } = {},
    ): Promise<{ code: number | null; body: string; httpCode: string; connectCode: string }> {
      const run = await runCommand(
        CURL as string,
        ["-q", "-sS", "-w", "\\n%{http_code} %{http_connect}", ...WIN32_CURL_TLS, ...args],
        { stdin: opts.stdin, env: opts.env ?? inherited() },
      );
      outputs.push(run.stdout, run.stderr);
      const lines = run.stdout.split("\n");
      const [httpCode = "", connectCode = ""] = (lines.at(-1) ?? "").trim().split(" ");
      return { code: run.code, body: lines.slice(0, -1).join("\n"), httpCode, connectCode };
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

    function startDaemon(withRuntimeDir: boolean, ready: RegExp) {
      return startCliServerOnFreePort(
        (port) => [
          "server",
          "start",
          "--proxy",
          "--proxy-port",
          String(port),
          "--session",
          "memory",
          ...(withRuntimeDir ? ["--runtime-dir", runtimeDir] : []),
        ],
        {
          vaultDir,
          env: { ...process.env, NODE_EXTRA_CA_CERTS: fixtureCaFile },
          ready: (server) => server.waitForStderr(ready),
        },
      );
    }

    beforeAll(async () => {
      root = mkdtempSync(join(tmpdir(), "harpoc-connect-"));
      vaultDir = join(root, "vault");
      srv = join(root, "srv");
      mkdirSync(vaultDir);
      mkdirSync(srv);
      writeFileSync(join(root, "empty.gitconfig"), "");
      fixtureCaFile = join(root, "fixture-ca.pem");
      writeFileSync(fixtureCaFile, GIT_SMART_HTTPS_CA_PEM);
      if (process.platform !== "win32") {
        // The consumer directory the daemon writes ca.pem into: 0750, the daemon's own (DB-14).
        runtimeDir = join(root, "run");
        mkdirSync(join(runtimeDir, AGENT), { recursive: true });
        chmodSync(runtimeDir, 0o750);
        chmodSync(join(runtimeDir, AGENT), 0o750);
      }

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
      await cli(["secret", "connection", "secret://git-cred", "--http-ca", fixtureCaFile]);
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
    }, 180_000);

    afterAll(async () => {
      try {
        await fixture?.close();
      } finally {
        if (root !== "") {
          rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
        }
      }
    });

    describe("before a CA is enrolled", () => {
      let daemon: CliServer | undefined;
      let proxyPort = 0;

      beforeAll(async () => {
        const started = await startDaemon(false, PROXY_READY);
        daemon = started.server;
        proxyPort = started.port;
      }, 60_000);

      afterAll(async () => {
        await daemon?.stop();
        if (daemon !== undefined) outputs.push(daemon.stdoutSoFar(), daemon.stderrSoFar());
      });

      it("CONNECT answers 501 with connection: close, before authentication, naming harpoc proxy ca init", async () => {
        const answer = await rawConnect(proxyPort, fixtureHost(), {});
        expect(answer.status).toBe(501);
        expect(answer.headers.connection).toEqual(["close"]);
        expect(answer.headers["proxy-authenticate"]).toBeUndefined();
        expect((JSON.parse(answer.body) as { message: string }).message).toContain(
          "harpoc proxy ca init",
        );
        expect(fixture?.requests.length).toBe(0);
      }, 60_000);
    });

    describe("with the Harpoc CA enrolled for 127.0.0.1", () => {
      let daemon: CliServer | undefined;
      let proxyPort = 0;
      let caFile = "";
      let caPem = "";
      let initOutput = { stdout: "", stderr: "" };

      beforeAll(async () => {
        const init = await runCli(["proxy", "ca", "init", "--name-constraints", CA_HOST], {
          vaultDir,
        });
        outputs.push(init.stdout, init.stderr);
        expect(init.code, init.stderr).toBe(0);
        initOutput = { stdout: init.stdout, stderr: init.stderr };
        caFile = join(root, "harpoc-root.pem");
        await cli(["proxy", "ca", "export", "--out", caFile]);
        caPem = readFileSync(caFile, "utf8");
        // The CA is loaded once at the start: the daemon is started after init (no hot reload).
        const started = await startDaemon(process.platform !== "win32", CONNECT_READY);
        daemon = started.server;
        proxyPort = started.port;
      }, 60_000);

      afterAll(async () => {
        await daemon?.stop();
      });

      it("proxy ca init names the constrained host and prints no key; export writes the root certificate", () => {
        expect(initOutput.stdout).toContain(CA_HOST);
        expect(initOutput.stderr.includes("Note:")).toBe(false);
        const ca = new X509Certificate(caPem);
        expect(ca.ca).toBe(true);
        expect(ca.checkIssued(ca)).toBe(true);
        expect(caPem.trimStart().startsWith("-----BEGIN CERTIFICATE-----")).toBe(true);
        for (const needle of PRIVATE_KEY_NEEDLES) {
          expect(canon(caPem).includes(needle)).toBe(false);
          expect(canon(initOutput.stdout).includes(needle)).toBe(false);
        }
      });

      it("the tunnel for 127.0.0.1 presents a leaf and the intermediate that issued it under the exported root, the chain verified by Node's TLS", async () => {
        const root = new X509Certificate(caPem);
        const { leaf, issuer } = await tunnelChain(proxyPort, fixtureHost(), useToken, caPem);
        expect(leaf.ca).toBe(false);
        expect(leaf.checkIssued(issuer)).toBe(true);
        expect(leaf.verify(issuer.publicKey)).toBe(true);
        expect(issuer.ca).toBe(true);
        expect(issuer.checkIssued(root)).toBe(true);
        expect(issuer.verify(root.publicKey)).toBe(true);
        expect(issuer.fingerprint256 === root.fingerprint256).toBe(false);
        expect(leaf.checkIP(CA_HOST)).toBe(CA_HOST);
        expect(Date.parse(leaf.validTo) <= Date.parse(root.validTo)).toBe(true);
        // The tunnel was opened and closed without a request: the fixture saw nothing.
        expect(brokered()).toHaveLength(0);
      }, 60_000);

      it.skipIf(CURL === null)(
        "curl --proxy with the token on stdin and --cacert: the placeholder as the Basic password is brokered inside the tunnel and the value in the response redacted (skipped where curl does not resolve)",
        async () => {
          const run = await curl(
            [
              "--proxy",
              `http://127.0.0.1:${String(proxyPort)}`,
              "--proxy-header",
              "@-",
              "--cacert",
              caFile,
              "-u",
              `${USER}:${PLACEHOLDER}`,
              `https://${fixtureHost()}/leaky.git/info/refs?service=git-upload-pack`,
            ],
            { stdin: `Proxy-Authorization: Bearer ${useToken}\n` },
          );
          expect(run.code).toBe(0);
          expect([run.httpCode, run.connectCode]).toEqual(["200", "200"]);
          expect(run.body.includes("refs/heads/[REDACTED]")).toBe(true);
          expect(run.body.includes(VALUE)).toBe(false);
          const last = brokered().at(-1);
          expect(last?.url).toBe("/leaky.git/info/refs?service=git-upload-pack");
          expect(last?.headers["proxy-authorization"]).toBeUndefined();
          expect(last?.headers["accept-encoding"]).toBe("identity");
        },
        60_000,
      );

      it("git clone through CONNECT: the fixture receives the real credential and never the placeholder or the token", async () => {
        const before = fixture?.requests.length ?? 0;
        const checkout = join(root, "clone");
        await git(
          root,
          ["clone", "-q", `https://${fixtureHost()}/repo.git`, checkout],
          connectGitEnv(proxyPort, caFile),
        );
        // DB-8's blind spot, pinned: the value inside git's zlib-compressed pack is no
        // literal byte run the redactor can match, so the checkout holds it.
        expect(readFileSync(join(checkout, "README.md"), "utf8") === SEED_README).toBe(true);
        expect((await git(checkout, ["config", "remote.origin.url"])).trim()).toBe(
          `https://${fixtureHost()}/repo.git`,
        );
        const seen = (fixture?.requests ?? []).slice(before);
        expect(seen.length).toBeGreaterThan(0);
        for (const r of seen) {
          const sent = JSON.stringify(r.headers);
          expect(r.headers["proxy-authorization"] === undefined).toBe(true);
          expect(sent.includes("harpoc:") || sent.includes(useToken)).toBe(false);
          expect([undefined, realBasic].includes(r.headers.authorization)).toBe(true);
        }
        // git's discovery request carries no credential — a pass-through inside the tunnel.
        expect(seen[0]?.headers.authorization === undefined).toBe(true);
        expect(seen[0]?.headers["accept-encoding"]).not.toBe("identity");
        const credentialed = seen.filter((r) => r.headers.authorization === realBasic);
        expect(credentialed.map((r) => `${r.method} ${r.url.split("?")[0]}`)).toEqual([
          "GET /repo.git/info/refs",
          "POST /repo.git/git-upload-pack",
          "POST /repo.git/git-upload-pack",
        ]);
        for (const r of credentialed) expect(r.headers["accept-encoding"]).toBe("identity");
      }, 60_000);

      it("git push through CONNECT lands the commit in the fixture's repository", async () => {
        const checkout = join(root, "clone");
        writeFileSync(join(checkout, "pushed.txt"), "pushed through the tunnel\n");
        await git(checkout, ["add", "pushed.txt"]);
        await git(checkout, ["commit", "-q", "-m", "through the tunnel"]);
        await git(checkout, ["push", "-q", "origin", "main"], connectGitEnv(proxyPort, caFile));
        const tip = await git(join(srv, "repo.git"), ["log", "-1", "--format=%s", "main"]);
        expect(tip.trim()).toBe("through the tunnel");
        expect(
          brokered().some(
            (r) => r.method === "POST" && r.url.startsWith("/repo.git/git-receive-pack"),
          ),
        ).toBe(true);
      }, 60_000);

      it("one secret.use row with context proxy per brokered request inside a tunnel — the tunnelled origin, the path without its query — and none for git's credential-less probes", async () => {
        const rows = (await auditRows(AuditEventType.SECRET_USE)).filter(
          (r) => r.detail?.["context"] === "proxy" && r.success,
        );
        const describeRow = (r: AuditRow): string =>
          `${String(r.detail?.["method"])} ${String(r.detail?.["path"])}`;
        const describeSeen = (r: SeenRequest): string => `${r.method} ${r.url.split("?")[0]}`;
        expect(rows.map(describeRow).sort()).toEqual(brokered().map(describeSeen).sort());
        for (const row of rows) {
          expect(row.principal_id).toBe(AGENT);
          expect(row.ip_address).toBe("127.0.0.1");
          expect(row.detail).toMatchObject({
            origin: `https://${fixtureHost()}`,
            status: 200,
            ca_pinned: true,
            interface: "proxy",
          });
          expect(row.detail?.["sanitized"]).toBe(
            row.detail?.["path"] === "/leaky.git/info/refs" ? true : undefined,
          );
        }
      }, 60_000);

      it("a CONNECT to a host outside the CA's constraints is refused 403 PROXY_CONNECT_DENIED before any contact and writes no row", async () => {
        const before = fixture?.requests.length;
        const rowsBefore = (await auditRows(AuditEventType.SECRET_USE)).length;
        const authority = `${OUTSIDE_HOST}:${fixturePort()}`;
        const answer = await rawConnect(proxyPort, authority, {
          "Proxy-Authorization": `Bearer ${useToken}`,
        });
        expect(answer.status).toBe(403);
        expect(answer.headers.connection).toEqual(["close"]);
        const body = JSON.parse(answer.body) as { error: string; message: string };
        expect(body.error).toBe(ErrorCode.PROXY_CONNECT_DENIED);
        expect(body.message).toContain(OUTSIDE_HOST);
        expect(body.message).toContain(fixturePort());
        expect(answer.body.includes(useToken)).toBe(false);
        expect(fixture?.requests.length).toBe(before);
        expect((await auditRows(AuditEventType.SECRET_USE)).length).toBe(rowsBefore);
      }, 60_000);

      it.skipIf(CURL === null)(
        "curl reports the refused tunnel: the proxy's 403 as http_connect and a non-zero exit, nothing received (skipped where curl does not resolve)",
        async () => {
          const before = fixture?.requests.length;
          const run = await curl(
            [
              "--proxy",
              `http://127.0.0.1:${String(proxyPort)}`,
              "--proxy-header",
              "@-",
              "--cacert",
              caFile,
              `https://${OUTSIDE_HOST}:${fixturePort()}/repo.git/info/refs`,
            ],
            { stdin: `Proxy-Authorization: Bearer ${useToken}\n` },
          );
          // curl's code for a refused tunnel differs by version (8.16.0: 56; 8.21.0: 7).
          expect(run.code === 0).toBe(false);
          expect([run.httpCode, run.connectCode]).toEqual(["000", "403"]);
          expect(fixture?.requests.length).toBe(before);
        },
        60_000,
      );

      it("a CONNECT without Proxy-Authorization is refused 407 with the Basic and Bearer challenges, an invalid token 401, neither reaching the fixture", async () => {
        const before = fixture?.requests.length;
        const missing = await rawConnect(proxyPort, fixtureHost(), {});
        expect(missing.status).toBe(407);
        expect(missing.headers["proxy-authenticate"]).toEqual([
          'Basic realm="harpoc"',
          'Bearer realm="harpoc"',
        ]);
        expect(missing.headers.connection).toEqual(["close"]);
        const invalid = await rawConnect(proxyPort, fixtureHost(), {
          "Proxy-Authorization": `Basic ${Buffer.from("harpoc:not-a-token").toString("base64")}`,
        });
        expect(invalid.status).toBe(401);
        expect((JSON.parse(invalid.body) as { error: string }).error).toBe(ErrorCode.INVALID_TOKEN);
        expect(invalid.headers["www-authenticate"]).toEqual(['Bearer realm="harpoc"']);
        expect(fixture?.requests.length).toBe(before);
      }, 60_000);

      it.skipIf(CURL === null)(
        "inside a tunnel the allowlist still decides: a placeholder sent to 127.0.0.1:1 is refused 403 URL_NOT_ALLOWED with a failed secret.use row naming the origin (skipped where curl does not resolve)",
        async () => {
          // Port 1 accepts nothing: a contact attempt would surface as 502, not 403.
          const run = await curl(
            [
              "--proxy",
              `http://127.0.0.1:${String(proxyPort)}`,
              "--proxy-header",
              "@-",
              "--cacert",
              caFile,
              "-u",
              `${USER}:${PLACEHOLDER}`,
              `https://${CA_HOST}:1/repo.git/info/refs`,
            ],
            { stdin: `Proxy-Authorization: Bearer ${useToken}\n` },
          );
          expect([run.httpCode, run.connectCode]).toEqual(["403", "200"]);
          expect((JSON.parse(run.body) as { error: string }).error).toBe(ErrorCode.URL_NOT_ALLOWED);
          const failed = (await auditRows(AuditEventType.SECRET_USE)).filter(
            (r) => r.detail?.["context"] === "proxy" && !r.success,
          );
          expect(failed).toHaveLength(1);
          expect(failed[0]?.detail).toMatchObject({
            origin: `https://${CA_HOST}:1`,
            error: ErrorCode.URL_NOT_ALLOWED,
          });
        },
        60_000,
      );

      it.skipIf(CURL === null)(
        "the plain-HTTP base-URL form is brokered unchanged beside the CA (skipped where curl does not resolve)",
        async () => {
          const run = await curl(
            [
              "-H",
              "@-",
              "-u",
              `${USER}:${PLACEHOLDER}`,
              `http://127.0.0.1:${String(proxyPort)}/${fixtureHost()}/leaky.git/info/refs?service=git-upload-pack`,
            ],
            { stdin: `Proxy-Authorization: Bearer ${useToken}\n` },
          );
          expect(run.code).toBe(0);
          expect(run.body.includes("refs/heads/[REDACTED]")).toBe(true);
          expect(run.body.includes(VALUE)).toBe(false);
        },
        60_000,
      );

      // A win32 consumer directory must be named for a local account (B7), and Schannel curl reads
      // no CA from the environment (curl's manual: CURL_CA_BUNDLE only "if the TLS backend is not
      // Schannel") — the consumer-directory row runs off win32.
      it.skipIf(process.platform === "win32" || CURL === null)(
        "the consumer directory holds the CA as ca.pem, proxy env names it, and curl trusts it from the environment with the token in HTTPS_PROXY (POSIX; skipped where curl does not resolve)",
        async () => {
          const caInDir = join(runtimeDir, AGENT, "ca.pem");
          expect(new X509Certificate(readFileSync(caInDir, "utf8")).fingerprint256).toBe(
            new X509Certificate(caPem).fingerprint256,
          );
          const printed = JSON.parse(
            await cli([
              "proxy",
              "env",
              AGENT,
              "secret://git-cred",
              "--runtime-dir",
              runtimeDir,
              "--proxy-port",
              String(proxyPort),
              "--json",
            ]),
          ) as Record<string, string>;
          for (const name of [
            "HARPOC_PROXY_CA_FILE",
            "SSL_CERT_FILE",
            "NODE_EXTRA_CA_CERTS",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "GIT_SSL_CAINFO",
          ]) {
            expect(printed[name], name).toBe(caInDir);
          }
          const run = await curl(
            [
              "-u",
              `${USER}:${PLACEHOLDER}`,
              `https://${fixtureHost()}/leaky.git/info/refs?service=git-upload-pack`,
            ],
            {
              env: {
                ...inherited(),
                HTTPS_PROXY: `http://harpoc:${useToken}@127.0.0.1:${String(proxyPort)}`,
                CURL_CA_BUNDLE: printed["CURL_CA_BUNDLE"],
              },
            },
          );
          expect(run.code).toBe(0);
          expect([run.httpCode, run.connectCode]).toEqual(["200", "200"]);
          expect(run.body.includes("refs/heads/[REDACTED]")).toBe(true);
        },
        60_000,
      );

      it("the CA's private key, the value and the token reach no output: the daemon's, the clients', the CLI's, the exported and the distributed CA, the audit trail", async () => {
        expect(PRIVATE_KEY_NEEDLES.length).toBeGreaterThan(0);
        const trail = await cli(["audit", "--limit", "500", "--json"]);
        const files = [caPem];
        if (process.platform !== "win32")
          files.push(readFileSync(join(runtimeDir, AGENT, "ca.pem"), "utf8"));
        const swept = [
          daemon?.stdoutSoFar() ?? "",
          daemon?.stderrSoFar() ?? "",
          trail,
          ...files,
          ...outputs,
        ];
        for (const text of swept) {
          expect(text.includes(VALUE)).toBe(false);
          expect(text.includes(useToken)).toBe(false);
          for (const needle of PRIVATE_KEY_NEEDLES)
            expect(canon(text).includes(needle)).toBe(false);
        }
      }, 60_000);

      it("the listener writes its server.start row with the bound port, and the CA is read once at the start", async () => {
        const rows = (await auditRows(AuditEventType.SERVER_START)).filter(
          (r) => r.detail?.["transport"] === "proxy" && r.detail?.["port"] === proxyPort,
        );
        expect(rows).toHaveLength(1);
        expect(rows[0]?.success).toBe(true);
        expect(rows[0]?.detail).toMatchObject({ port: proxyPort, host: "127.0.0.1" });
        const caIssued = (await auditRows(AuditEventType.CERT_ISSUE)).filter(
          (r) => r.detail?.["action"] === "proxy_ca_init" && r.success,
        );
        expect(caIssued).toHaveLength(1);
        const caReads = (await auditRows(AuditEventType.SECRET_READ)).filter(
          (r) => r.detail?.["config"] === "certificate_private_key",
        );
        expect(caReads).toHaveLength(1);
        expect(caReads[0]?.success).toBe(true);
        expect(caReads[0]?.secret_id).toBe(caIssued[0]?.secret_id);
      }, 60_000);

      // Windows has no SIGTERM: child.kill() terminates the process without running
      // its handler, so no server.stop row is written there.
      it.skipIf(process.platform === "win32")(
        "the daemon stops on SIGTERM with no tunnel left open and writes the proxy listener's server.stop row (POSIX: SIGTERM runs the handler)",
        async () => {
          const server = daemon as CliServer;
          await server.stop();
          expect(server.child.exitCode).toBe(0);
          const rows = (await auditRows(AuditEventType.SERVER_STOP)).filter(
            (r) => r.detail?.["transport"] === "proxy" && r.detail?.["port"] === proxyPort,
          );
          expect(rows).toHaveLength(1);
          expect(rows[0]?.detail).toMatchObject({ port: proxyPort, trigger: "SIGTERM" });
        },
        60_000,
      );
    });
  },
);
