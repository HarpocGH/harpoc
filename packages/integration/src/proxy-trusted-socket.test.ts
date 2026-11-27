import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer, request } from "node:http";
import type { IncomingHttpHeaders } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import {
  RAW_GET_TIMEOUT_MS,
  freePort,
  runCli,
  startCliServerOnFreePort,
} from "./helpers/spawn-cli.js";
import type { CliServer } from "./helpers/spawn-cli.js";
import { expectAbsent } from "@harpoc/test-utils";

/**
 * The trusted consumer socket on the built CLI: `server start --proxy --proxy-trust-socket
 * agent=<name>,secrets=<pattern>` on a real vault serves `<consumer>/proxy-trusted.sock` in the
 * opted-in consumer directory, where a request without `Proxy-Authorization` is brokered as that
 * consumer, while `proxy.sock` beside it keeps asking for a token. The upstream is a `node:http`
 * server on 127.0.0.1 that an `http://` entry of the secret names, as in the plain reading's suite.
 */

const PASSWORD = "proxy-trusted-socket-master-pw-1";
const ARGON2_TIMEOUT_MS = 110_000;
const CONSUMER = "agent1";
const OTHER = "agent2";
const REGISTERED_ONLY = "agent3";
const VALUE = "trusted-socket-fixture-key-7c1d";
const PLACEHOLDER = "harpoc:api-key";
const SPEC = `agent=${CONSUMER},secrets=api-key`;
const PROXY_READY =
  /\[harpoc\] egress proxy listening on http:\/\/127\.0\.0\.1:\d+ and 2 consumer sockets \(<consumer>\/proxy\.sock\) and 1 trusted socket \(<consumer>\/proxy-trusted\.sock\)/;
const START_FAILURE_BOUND_MS = 15_000;

interface AuditRow {
  id: number;
  event_type: string;
  secret_id: string | null;
  principal_id: string | null;
  ip_address: string | null;
  success: boolean;
  detail: Record<string, unknown> | null;
}

interface SeenRequest {
  url: string;
  headers: IncomingHttpHeaders;
}

interface PlainServer {
  port: number;
  requests: SeenRequest[];
  close(): Promise<void>;
}

function socketGet(
  socketPath: string,
  path: string,
  headers: Record<string, string>,
): Promise<{ status: number; headers: IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request({ socketPath, path, method: "GET", headers, agent: false }, (res) => {
      let data = "";
      res.on("data", (chunk: Buffer) => (data += chunk.toString("utf8")));
      res.on("end", () =>
        resolve({ status: res.statusCode ?? 0, headers: res.headers, body: data }),
      );
    });
    req.on("error", reject);
    req.setTimeout(RAW_GET_TIMEOUT_MS, () => {
      req.destroy(
        new Error(
          `socketGet ${path} on ${socketPath} timed out after ${String(RAW_GET_TIMEOUT_MS)} ms`,
        ),
      );
    });
    req.end();
  });
}

async function startPlainServer(): Promise<PlainServer> {
  const requests: SeenRequest[] = [];
  const server = createServer((req, res) => {
    requests.push({ url: req.url ?? "/", headers: req.headers });
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  return {
    port: (server.address() as AddressInfo).port,
    requests,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  };
}

// The trusted socket is a Unix socket: the proxy refuses it on Windows, and so does the option.
describe.skipIf(process.platform === "win32")(
  "the trusted consumer socket on the built CLI (server start --proxy --proxy-trust-socket)",
  () => {
    let root = "";
    let vaultDir = "";
    let runtimeDir = "";
    let upstream: PlainServer | undefined;
    let daemon: CliServer | undefined;
    const daemons: CliServer[] = [];
    const outputs: string[] = [];

    const trustedOf = (consumer: string): string =>
      join(runtimeDir, consumer, "proxy-trusted.sock");
    const proxySockOf = (consumer: string): string => join(runtimeDir, consumer, "proxy.sock");
    const upstreamHost = (): string => `127.0.0.1:${String(upstream?.port)}`;

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

    async function nonReadRows(): Promise<AuditRow[]> {
      return JSON.parse(
        await cli([
          "audit",
          "--exclude-event",
          AuditEventType.VAULT_READ,
          "--limit",
          "500",
          "--json",
        ]),
      ) as AuditRow[];
    }

    const proxyUseRows = async (): Promise<AuditRow[]> =>
      (await auditRows(AuditEventType.SECRET_USE)).filter(
        (row) => row.detail?.["context"] === "proxy",
      );

    function brokered(socketPath: string, path: string): ReturnType<typeof socketGet> {
      return socketGet(socketPath, `/${upstreamHost()}${path}`, {
        authorization: `Bearer ${PLACEHOLDER}`,
      });
    }

    async function startDaemon(): Promise<CliServer> {
      const { server } = await startCliServerOnFreePort(
        (port) => [
          "server",
          "start",
          "--session",
          "memory",
          "--proxy",
          "--proxy-port",
          String(port),
          "--runtime-dir",
          runtimeDir,
          "--proxy-trust-socket",
          SPEC,
        ],
        { vaultDir, ready: (child) => child.waitForStderr(PROXY_READY) },
      );
      daemons.push(server);
      return server;
    }

    beforeAll(async () => {
      root = mkdtempSync(join(tmpdir(), "harpoc-pts-"));
      vaultDir = join(root, "vault");
      runtimeDir = join(root, "run");
      mkdirSync(vaultDir);
      mkdirSync(runtimeDir, { mode: 0o750 });
      chmodSync(runtimeDir, 0o750);
      for (const consumer of [CONSUMER, OTHER]) {
        mkdirSync(join(runtimeDir, consumer), { mode: 0o750 });
        chmodSync(join(runtimeDir, consumer), 0o750);
      }
      upstream = await startPlainServer();

      // init leaves the vault unlocked with a session file, which the memory-session daemons load.
      await cli(["init"], `${PASSWORD}\n${PASSWORD}\n`, ARGON2_TIMEOUT_MS);
      for (const agent of [CONSUMER, OTHER, REGISTERED_ONLY]) {
        await cli(["agent", "register", agent]);
      }
      await cli(["secret", "set", "api-key"], `${VALUE}\n`);
      await cli([
        "secret",
        "allow",
        "secret://api-key",
        "--url",
        `http://${upstreamHost()}/*`,
        "--proxy",
      ]);
      await cli([
        "policy",
        "grant",
        "secret://api-key",
        "--principal-type",
        "agent",
        "--principal-id",
        CONSUMER,
        "--permissions",
        "use",
      ]);

      daemon = await startDaemon();
    }, 180_000);

    afterAll(async () => {
      try {
        for (const server of daemons) await server.stop();
      } finally {
        try {
          await upstream?.close();
        } finally {
          if (root !== "") {
            rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
          }
        }
      }
    });

    it("serves proxy-trusted.sock 0660 in the opted-in consumer directory alone, beside proxy.sock, with a server.start row of its own: transport proxy, tokenless, the consumer", async () => {
      const trusted = lstatSync(trustedOf(CONSUMER));
      expect(trusted.isSocket()).toBe(true);
      expect((trusted.mode & 0o777).toString(8)).toBe("660");
      for (const consumer of [CONSUMER, OTHER]) {
        expect(lstatSync(proxySockOf(consumer)).isSocket()).toBe(true);
      }
      expect(existsSync(trustedOf(OTHER))).toBe(false);

      const rows = (await auditRows(AuditEventType.SERVER_START)).filter(
        (row) => row.detail?.["transport"] === "proxy",
      );
      expect(rows.map((row) => row.detail?.["tokenless"]).sort()).toEqual([false, true]);
      const trustedRows = rows.filter((row) => row.detail?.["tokenless"] === true);
      expect(trustedRows.map((row) => [row.success, row.principal_id, row.detail])).toEqual([
        [
          true,
          null,
          { transport: "proxy", tokenless: true, tty_prompt: false, consumer: CONSUMER },
        ],
      ]);
    }, 60_000);

    it("a request without a token on proxy-trusted.sock is brokered as the consumer: the upstream sees the stored value, and the secret.use row carries tokenless: true", async () => {
      const served = await brokered(trustedOf(CONSUMER), "/v1/served");
      expect(served.status).toBe(200);
      expect(served.body).toBe("ok");
      const seen = upstream?.requests.at(-1);
      expect(seen?.url).toBe("/v1/served");
      expect(seen?.headers.authorization === `Bearer ${VALUE}`).toBe(true);
      expect(seen?.headers["proxy-authorization"] === undefined).toBe(true);

      const rows = (await proxyUseRows()).filter((row) => row.detail?.["path"] === "/v1/served");
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ success: true, principal_id: CONSUMER, ip_address: null });
      expect(rows[0]?.secret_id).toEqual(expect.any(String));
      expect(rows[0]?.detail).toMatchObject({
        context: "proxy",
        interface: "proxy",
        method: "GET",
        origin: `http://${upstreamHost()}`,
        plain_http: true,
        status: 200,
        tokenless: true,
      });
    }, 60_000);

    it("the same request on proxy.sock is answered 407 and reaches neither the upstream nor the trail", async () => {
      const before = upstream?.requests.length;
      const rowsBefore = (await proxyUseRows()).length;

      const refused = await brokered(proxySockOf(CONSUMER), "/v1/refused");
      expect(refused.status).toBe(407);
      expect(refused.headers["proxy-authenticate"]).toBe(
        'Basic realm="harpoc", Bearer realm="harpoc"',
      );
      expect(upstream?.requests.length).toBe(before);
      expect((await proxyUseRows()).length).toBe(rowsBefore);
    }, 60_000);

    it("after agent deactivate the next request on proxy-trusted.sock is 403 AGENT_INACTIVE with one tokenless access.denied row, and never reaches the upstream", async () => {
      const before = upstream?.requests.length;
      const deniedBefore = (await auditRows(AuditEventType.ACCESS_DENIED)).length;
      await cli(["agent", "deactivate", CONSUMER]);
      try {
        const refused = await brokered(trustedOf(CONSUMER), "/v1/inactive");
        expect(refused.status).toBe(403);
        expect((JSON.parse(refused.body) as { error: string }).error).toBe(
          ErrorCode.AGENT_INACTIVE,
        );
      } finally {
        await cli(["agent", "activate", CONSUMER]);
      }
      expect(upstream?.requests.length).toBe(before);

      const denied = await auditRows(AuditEventType.ACCESS_DENIED);
      expect(denied.length - deniedBefore).toBe(1);
      expect(denied[0]).toMatchObject({
        success: false,
        secret_id: null,
        principal_id: CONSUMER,
        ip_address: null,
      });
      expect(denied[0]?.detail).toEqual({
        operation: `GET https://${upstreamHost()}`,
        error: ErrorCode.AGENT_INACTIVE,
        reason: "proxy",
        interface: "proxy",
        tokenless: true,
      });
    }, 60_000);

    it("the daemon stops on SIGTERM: one tokenless server.stop row naming the consumer beside the proxy's own, and proxy-trusted.sock is removed", async () => {
      const server = daemon as CliServer;
      await server.stop();
      expect(server.child.exitCode).toBe(0);

      const rows = (await auditRows(AuditEventType.SERVER_STOP)).filter(
        (row) => row.detail?.["transport"] === "proxy",
      );
      expect(rows.map((row) => row.detail?.["tokenless"]).sort()).toEqual([false, true]);
      const trustedRows = rows.filter((row) => row.detail?.["tokenless"] === true);
      expect(trustedRows.map((row) => row.detail)).toEqual([
        {
          transport: "proxy",
          tokenless: true,
          consumer: CONSUMER,
          uptime_ms: expect.any(Number),
          trigger: "SIGTERM",
        },
      ]);
      expect(existsSync(trustedOf(CONSUMER))).toBe(false);
      expect(existsSync(proxySockOf(CONSUMER))).toBe(false);
    }, 60_000);

    it.each([
      { label: "Agent1, beside the directory agent1 (case alone)", agent: "Agent1" },
      { label: "agent3, registered without a consumer directory", agent: REGISTERED_ONLY },
    ])(
      "refuses a spec naming $label INVALID_INPUT before the vault opens: the one line, exit 1, no row",
      async ({ agent }) => {
        const rowsBefore = (await nonReadRows()).length;
        const port = await freePort();
        const run = await runCli(
          [
            "server",
            "start",
            "--session",
            "memory",
            "--proxy",
            "--proxy-port",
            String(port),
            "--runtime-dir",
            runtimeDir,
            "--proxy-trust-socket",
            `agent=${agent},secrets=api-key`,
          ],
          { vaultDir },
        );
        outputs.push(run.stdout, run.stderr);

        expect(run.code).toBe(1);
        expect(run.stderr).toBe(
          `Error: [INVALID_INPUT] --proxy-trust-socket: agent "${agent}" has no consumer directory under ${runtimeDir}\n`,
        );
        expect(existsSync(proxySockOf(CONSUMER))).toBe(false);
        expect((await nonReadRows()).length).toBe(rowsBefore);
      },
      60_000,
    );

    it("a stale proxy-trusted.sock left by a killed daemon is cleared by the next start's ladder, as proxy.sock's is, and served again", async () => {
      const killed = await startDaemon();
      killed.child.kill("SIGKILL");
      await killed.closed();
      expect(lstatSync(trustedOf(CONSUMER)).isSocket()).toBe(true);
      expect(lstatSync(proxySockOf(CONSUMER)).isSocket()).toBe(true);

      const restarted = await startDaemon();
      try {
        const served = await brokered(trustedOf(CONSUMER), "/v1/after-kill");
        expect(served.status).toBe(200);
        expect(upstream?.requests.at(-1)?.url).toBe("/v1/after-kill");
      } finally {
        await restarted.stop();
      }
      expect(restarted.child.exitCode).toBe(0);
      expect(existsSync(trustedOf(CONSUMER))).toBe(false);
    }, 120_000);

    it("a regular file named proxy-trusted.sock in the consumer directory refuses the start after the proxy came up: Error: [INVALID_INPUT] Egress proxy socket: <path> exists and is not a socket, exit 1, the file kept, no trusted socket's row", async () => {
      const regularFile = trustedOf(CONSUMER);
      writeFileSync(regularFile, "");
      try {
        const trustedRowsOf = (rows: AuditRow[], event: string): number =>
          rows.filter(
            (row) =>
              row.event_type === event &&
              row.detail?.["transport"] === "proxy" &&
              row.detail["tokenless"] === true,
          ).length;
        const startsBefore = await auditRows(AuditEventType.SERVER_START);
        const stopsBefore = await auditRows(AuditEventType.SERVER_STOP);
        const trustedStartsBefore = trustedRowsOf(startsBefore, AuditEventType.SERVER_START);
        const trustedStopsBefore = trustedRowsOf(stopsBefore, AuditEventType.SERVER_STOP);
        const { server, port } = await startCliServerOnFreePort(
          (p) => [
            "server",
            "start",
            "--session",
            "memory",
            "--proxy",
            "--proxy-port",
            String(p),
            "--runtime-dir",
            runtimeDir,
            "--proxy-trust-socket",
            SPEC,
          ],
          {
            vaultDir,
            ready: (child) =>
              child.waitForStderr(/exists and is not a socket/, START_FAILURE_BOUND_MS),
          },
        );
        daemons.push(server);
        const { code } = await server.closed(START_FAILURE_BOUND_MS);

        expect(code).toBe(1);
        expect(
          server
            .stderrSoFar()
            .split(/\r?\n/)
            .filter((line) => /^(?:Error|Fatal):/.test(line)),
        ).toEqual([
          `Error: [INVALID_INPUT] Egress proxy socket: ${regularFile} exists and is not a socket`,
        ]);
        const kept = lstatSync(regularFile);
        expect(kept.isFile()).toBe(true);
        expect(existsSync(proxySockOf(CONSUMER))).toBe(false);
        expect(existsSync(proxySockOf(OTHER))).toBe(false);

        const proxyRows = [
          ...(await auditRows(AuditEventType.SERVER_START)),
          ...(await auditRows(AuditEventType.SERVER_STOP)),
        ]
          .filter((row) => row.detail?.["transport"] === "proxy")
          .sort((a, b) => a.id - b.id);
        expect(
          proxyRows
            .filter((row) => row.detail?.["port"] === port)
            .map((row) => [row.event_type, row.detail?.["trigger"]]),
        ).toEqual([
          [AuditEventType.SERVER_START, undefined],
          [AuditEventType.SERVER_STOP, "start_failed"],
        ]);
        expect(trustedRowsOf(proxyRows, AuditEventType.SERVER_START)).toBe(trustedStartsBefore);
        expect(trustedRowsOf(proxyRows, AuditEventType.SERVER_STOP)).toBe(trustedStopsBefore);
      } finally {
        rmSync(regularFile, { force: true });
      }
    }, 60_000);

    it("the stored value reaches no daemon's output, no CLI output and not the audit trail", async () => {
      const trail = await cli(["audit", "--limit", "500", "--json"]);
      const swept = [
        ...daemons.flatMap((server) => [server.stdoutSoFar(), server.stderrSoFar()]),
        trail,
        ...outputs,
      ];
      for (const text of swept) expectAbsent(text, VALUE, "a swept output");
    }, 60_000);
  },
);
