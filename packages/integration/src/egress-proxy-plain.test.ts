import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, request } from "node:http";
import type { IncomingHttpHeaders, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import { RAW_GET_TIMEOUT_MS, runCli, startCliServerOnFreePort } from "./helpers/spawn-cli.js";
import type { CliServer } from "./helpers/spawn-cli.js";
import { expectAbsent } from "@harpoc/test-utils";

/**
 * The egress proxy's plain reading end to end: the built CLI's `server start
 * --proxy` on a real vault, a placeholder sent in clear to a `node:http` server
 * on 127.0.0.1 that an `http://` entry of the secret names, and nowhere else.
 */

const PASSWORD = "egress-proxy-plain-master-pw-1";
const ARGON2_TIMEOUT_MS = 110_000;
const AGENT = "agent-plain";
const VALUE = "plain-fixture-pw-4e2b";
const PLACEHOLDER = "harpoc:plain-cred";
const PROXY_READY = /\[harpoc\] egress proxy listening on http:\/\/127\.0\.0\.1:(\d+)/;

interface AuditRow {
  event_type: string;
  success: boolean;
  detail: Record<string, unknown> | null;
}

interface SeenRequest {
  method: string;
  url: string;
  headers: IncomingHttpHeaders;
}

interface PlainServer {
  port: number;
  requests: SeenRequest[];
  close(): Promise<void>;
}

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

async function startPlainServer(
  answer: (url: string, res: ServerResponse) => void,
): Promise<PlainServer> {
  const requests: SeenRequest[] = [];
  const server = createServer((req, res) => {
    requests.push({ method: req.method ?? "GET", url: req.url ?? "/", headers: req.headers });
    answer(req.url ?? "/", res);
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

describe("egress proxy, the plain reading end to end (built CLI)", () => {
  let root = "";
  let vaultDir = "";
  let a: PlainServer | undefined;
  let b: PlainServer | undefined;
  let daemon: CliServer | undefined;
  let proxyPort = 0;
  let useToken = "";
  const outputs: string[] = [];

  const hostA = (): string => `127.0.0.1:${String(a?.port)}`;
  const hostB = (): string => `127.0.0.1:${String(b?.port)}`;

  async function cli(args: string[], stdin?: string, timeoutMs?: number): Promise<string> {
    const run = await runCli(args, { vaultDir, stdin, timeoutMs });
    outputs.push(run.stdout, run.stderr);
    expect(run.code, `${args.join(" ")}: ${run.stderr}`).toBe(0);
    return run.stdout;
  }

  async function proxyRows(): Promise<AuditRow[]> {
    const rows = JSON.parse(
      await cli(["audit", "--event", AuditEventType.SECRET_USE, "--limit", "500", "--json"]),
    ) as AuditRow[];
    return rows.filter((r) => r.detail?.["context"] === "proxy");
  }

  function brokered(path: string): ReturnType<typeof rawGet> {
    return rawGet(proxyPort, path, {
      authorization: `Bearer ${PLACEHOLDER}`,
      "proxy-authorization": `Bearer ${useToken}`,
    });
  }

  beforeAll(async () => {
    root = mkdtempSync(join(tmpdir(), "harpoc-egress-proxy-plain-"));
    vaultDir = join(root, "vault");
    mkdirSync(vaultDir);
    b = await startPlainServer((_url, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("b");
    });
    const next = `http://${hostB()}/next`;
    a = await startPlainServer((url, res) => {
      if (url === "/redirect") {
        res.writeHead(302, { location: next });
        res.end();
        return;
      }
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("a");
    });

    await cli(["init"], `${PASSWORD}\n${PASSWORD}\n`, ARGON2_TIMEOUT_MS);
    await cli(["agent", "register", AGENT]);
    await cli(["secret", "set", "plain-cred"], `${VALUE}\n`);
    await cli([
      "secret",
      "allow",
      "secret://plain-cred",
      "--url",
      `http://${hostA()}/*`,
      "--proxy",
    ]);
    await cli([
      "policy",
      "grant",
      "secret://plain-cred",
      "--principal-type",
      "agent",
      "--principal-id",
      AGENT,
      "--permissions",
      "use",
    ]);
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

    const started = await startCliServerOnFreePort(
      (port) => ["server", "start", "--proxy", "--proxy-port", String(port), "--session", "memory"],
      { vaultDir, ready: (server) => server.waitForStderr(PROXY_READY) },
    );
    daemon = started.server;
    proxyPort = started.port;
  }, 180_000);

  afterAll(async () => {
    try {
      await daemon?.stop();
    } finally {
      try {
        await Promise.all([a?.close(), b?.close()]);
      } finally {
        if (root !== "") {
          rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
        }
      }
    }
  });

  it("a mapped follow-up to a port without an entry is refused", async () => {
    const first = await brokered(`/${hostA()}/redirect`);
    expect(first.status).toBe(302);
    expect(first.headers.location).toBe(`/${hostB()}/next`);

    const followUp = await brokered(first.headers.location as string);
    expect(followUp.status).toBe(403);
    expect((JSON.parse(followUp.body) as { error: string }).error).toBe(ErrorCode.URL_NOT_ALLOWED);
    expect(b?.requests).toHaveLength(0);

    const failed = (await proxyRows()).filter((r) => !r.success);
    expect(failed).toHaveLength(1);
    expect(failed[0]?.detail).toMatchObject({
      origin: `https://${hostB()}`,
      path: "/next",
      error: ErrorCode.URL_NOT_ALLOWED,
    });
    expect("plain_http" in (failed[0]?.detail as object)).toBe(false);
  }, 60_000);

  it("served in clear on an http:// entry, refused once an https:// entry names the authority", async () => {
    const path = `/${hostA()}/api/authentication/validate`;
    const served = await brokered(path);
    expect(served.status).toBe(200);
    const seen = a?.requests.at(-1);
    expect(seen?.url).toBe("/api/authentication/validate");
    expect(seen?.headers.authorization === `Bearer ${VALUE}`).toBe(true);
    expect(seen?.headers["proxy-authorization"] === undefined).toBe(true);

    const row = (await proxyRows()).find(
      (r) => r.success && r.detail?.["path"] === "/api/authentication/validate",
    );
    expect(row?.detail).toMatchObject({
      origin: `http://${hostA()}`,
      status: 200,
      plain_http: true,
      interface: "proxy",
    });
    expect("ca_pinned" in (row?.detail as object)).toBe(false);

    const before = a?.requests.length;
    await cli([
      "secret",
      "allow",
      "secret://plain-cred",
      "--url",
      `http://${hostA()}/*`,
      "--url",
      `https://${hostA()}/none/*`,
    ]);
    const refused = await brokered(path);
    expect(refused.status).toBe(403);
    expect((JSON.parse(refused.body) as { error: string }).error).toBe(ErrorCode.URL_NOT_ALLOWED);
    expect(a?.requests.length).toBe(before);

    const failed = (await proxyRows()).filter(
      (r) => !r.success && r.detail?.["path"] === "/api/authentication/validate",
    );
    expect(failed).toHaveLength(1);
    expect(failed[0]?.detail).toMatchObject({
      origin: `https://${hostA()}`,
      error: ErrorCode.URL_NOT_ALLOWED,
    });
    expect("plain_http" in (failed[0]?.detail as object)).toBe(false);

    const trail = await cli(["audit", "--limit", "500", "--json"]);
    const swept = [daemon?.stdoutSoFar() ?? "", daemon?.stderrSoFar() ?? "", trail, ...outputs];
    for (const text of swept) {
      expectAbsent(text, VALUE, "a swept output");
      expectAbsent(text, useToken, "a swept output");
    }
  }, 60_000);
});
