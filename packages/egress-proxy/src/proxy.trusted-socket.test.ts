import { spawn } from "node:child_process";
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { Agent, request } from "node:http";
import type { OutgoingHttpHeaders } from "node:http";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TLSSocket } from "node:tls";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { MockInstance } from "vitest";
import { createCa } from "@harpoc/cert-manager";
import {
  ErrorCode,
  RATE_LIMIT_PROXY_REFUSALS,
  VaultError,
  proxySocketCaller,
} from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { createEgressProxy } from "./proxy.js";
import type { EgressProxy } from "./proxy.js";
import { RefusalBudget } from "./refusal-budget.js";
import { SECRET_VALUE, TOKENS, engineDouble } from "./__fixtures__/engine-double.js";
import type { EngineDouble } from "./__fixtures__/engine-double.js";
import { PROXY_CLIENT_TIMEOUT_MS, proxyRequest } from "./__fixtures__/proxy-client.js";
import type { ProxyReply } from "./__fixtures__/proxy-client.js";
import { exchangeInTunnel, openTunnel } from "./__fixtures__/tunnel-client.js";
import {
  CAN_SET_DEFAULT_CA,
  startUpstream,
  trustFixtureCaByDefault,
} from "./__fixtures__/upstream-server.js";
import type { UpstreamFixture } from "./__fixtures__/upstream-server.js";

const CONSUMER = "agent1";
const PATTERNS = ["api-key"];
const TRUSTED = proxySocketCaller(CONSUMER, PATTERNS);
const BUDGET_KEY = "agent:agent1";
const CHALLENGES = 'Basic realm="harpoc", Bearer realm="harpoc"';
const MISSING = { error: ErrorCode.INVALID_TOKEN, message: "Missing Proxy-Authorization header" };
const MALFORMED = {
  error: ErrorCode.INVALID_TOKEN,
  message: "Malformed Proxy-Authorization header",
};
const NOT_SERVED = {
  error: ErrorCode.ACCESS_DENIED,
  message: "Access denied: The trusted socket does not serve this secret",
};
const SPENT = { error: ErrorCode.RATE_LIMIT_EXCEEDED, message: "Proxy refusal budget exceeded" };

/** Every byte the proxy sends back on a raw connection to the Unix socket, until it closes. */
function rawSocketExchange(socketPath: string, text: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = connect(socketPath);
    const chunks: Buffer[] = [];
    socket.setTimeout(PROXY_CLIENT_TIMEOUT_MS, () =>
      socket.destroy(new Error("raw exchange timed out")),
    );
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.on("error", reject);
    socket.on("close", () => resolve(Buffer.concat(chunks).toString("latin1")));
    socket.write(text);
  });
}

/** Whether a connect to the Unix socket at `socketPath` is accepted. */
function socketAccepts(socketPath: string): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = connect(socketPath);
    probe.setTimeout(PROXY_CLIENT_TIMEOUT_MS, () => probe.destroy());
    probe.on("connect", () => {
      probe.destroy();
      resolve(true);
    });
    probe.on("error", () => resolve(false));
    probe.on("close", () => resolve(false));
  });
}

interface KeptReply {
  status: number;
  body: string;
  reused: boolean;
}

/** One request through a keep-alive agent of one socket, so a second request rides the first one's connection. */
function keptAliveRequest(
  agent: Agent,
  socketPath: string,
  path: string,
  headers: OutgoingHttpHeaders,
): Promise<KeptReply> {
  return new Promise((resolve, reject) => {
    const req = request({ socketPath, path, headers, agent }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("error", reject);
      res.on("end", () =>
        resolve({
          status: res.statusCode ?? 0,
          body: Buffer.concat(chunks).toString("utf8"),
          reused: req.reusedSocket,
        }),
      );
    });
    req.setTimeout(PROXY_CLIENT_TIMEOUT_MS, () =>
      req.destroy(new Error("proxy request timed out")),
    );
    req.on("error", reject);
    req.end();
  });
}

// A trusted socket exists on POSIX only: its directory's mode is the one
// factor, and Windows has none to rely on — proxy.listen.test.ts holds its refusal.
describe.skipIf(process.platform === "win32")("the trusted socket (POSIX)", () => {
  let upstream: UpstreamFixture;
  let dir: string;
  let path: string;
  let double: EngineDouble;
  let budget: RefusalBudget;
  let charge: MockInstance<RefusalBudget["charge"]>;
  let proxy: EgressProxy;

  beforeAll(async () => {
    upstream = await startUpstream();
  });

  afterAll(async () => {
    await upstream.close();
  });

  beforeEach(() => {
    upstream.seen.length = 0;
    upstream.script((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
    dir = mkdtempSync(join(tmpdir(), "harpoc-proxy-trust-"));
    path = join(dir, "proxy-trusted.sock");
    double = engineDouble();
    budget = new RefusalBudget();
    charge = vi.spyOn(budget, "charge");
    proxy = createEgressProxy({ engine: double.engine, refusalBudget: budget });
  });

  afterEach(async () => {
    await proxy.close();
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const listenTrusted = (): Promise<void> => proxy.listenTrustedSocket(path, CONSUMER, PATTERNS);

  /** A base-URL request to the upstream fixture, `POST /v1/messages` by default, on the trusted socket unless named. */
  function send(
    headers: OutgoingHttpHeaders,
    extra: { socketPath?: string; port?: number; method?: string; target?: string } = {},
  ): Promise<ProxyReply> {
    const method = extra.method ?? "POST";
    return proxyRequest({
      ...(extra.port === undefined
        ? { socketPath: extra.socketPath ?? path }
        : { port: extra.port }),
      path: extra.target ?? `/127.0.0.1:${upstream.port}/v1/messages`,
      method,
      headers,
      ...(method === "POST" ? { body: "{}" } : {}),
    });
  }

  describe("a request without Proxy-Authorization", () => {
    it("is brokered as the directory's consumer: the upstream gets the value, the gate and resolveForProxy the trusted caller, verifyToken nothing", async () => {
      await listenTrusted();

      const reply = await send({ "x-api-key": "harpoc:api-key" });

      expect(reply.status).toBe(200);
      expect(upstream.seen).toHaveLength(1);
      expect(upstream.seen[0]?.headers["x-api-key"]).toBe(SECRET_VALUE);
      expect(double.resolveForProxy).toHaveBeenCalledTimes(1);
      expect(double.resolveForProxy.mock.calls[0]?.[0]).toBe("secret://api-key");
      expect(double.resolveForProxy.mock.calls[0]?.[1]).toEqual(
        proxySocketCaller("agent1", ["api-key"]),
      );
      expect(double.assertProxyConsumer).toHaveBeenCalledTimes(1);
      expect(double.assertProxyConsumer).toHaveBeenCalledWith(TRUSTED);
      expect(double.assertProxyConsumer.mock.invocationCallOrder[0] as number).toBeLessThan(
        double.resolveForProxy.mock.invocationCallOrder[0] as number,
      );
      expect(double.verifyToken).not.toHaveBeenCalled();
      expect(double.leases[0]?.complete).toHaveBeenCalledTimes(1);
    });

    it("on a socket opened by listenSocket is 407 with both challenges; nothing is gated or resolved", async () => {
      const plain = join(dir, "proxy.sock");
      await proxy.listenSocket(plain);
      await listenTrusted();

      const reply = await send({ "x-api-key": "harpoc:api-key" }, { socketPath: plain });

      expect(reply.status).toBe(407);
      expect(reply.headers["proxy-authenticate"]).toBe(CHALLENGES);
      expect(JSON.parse(reply.body)).toEqual(MISSING);
      expect(double.assertProxyConsumer).not.toHaveBeenCalled();
      expect(double.resolveForProxy).not.toHaveBeenCalled();
      expect(upstream.seen).toHaveLength(0);
    });

    it("on the TCP listener is 407 with both challenges; nothing is gated or resolved", async () => {
      const { port } = await proxy.listenTcp(0, "127.0.0.1");
      await listenTrusted();

      const reply = await send({ "x-api-key": "harpoc:api-key" }, { port });

      expect(reply.status).toBe(407);
      expect(reply.headers["proxy-authenticate"]).toBe(CHALLENGES);
      expect(JSON.parse(reply.body)).toEqual(MISSING);
      expect(double.assertProxyConsumer).not.toHaveBeenCalled();
      expect(double.resolveForProxy).not.toHaveBeenCalled();
      expect(upstream.seen).toHaveLength(0);
    });
  });

  describe("a request that carries Proxy-Authorization is judged as on any listener", () => {
    it("a valid Bearer token is served with the token's caller, not the consumer, and no tokenless mark", async () => {
      await listenTrusted();

      const reply = await send({
        "proxy-authorization": `Bearer ${TOKENS.use}`,
        "x-api-key": "harpoc:api-key",
      });

      expect(reply.status).toBe(200);
      expect(double.verifyToken).toHaveBeenCalledWith(TOKENS.use);
      const caller = double.resolveForProxy.mock.calls[0]?.[1];
      expect(caller).toEqual({
        principal_type: "agent",
        principal_id: "agent-a",
        interface: "proxy",
      });
      expect("tokenless" in (caller as object)).toBe(false);
      expect(double.assertProxyConsumer).not.toHaveBeenCalled();
    });

    it.each([
      ["empty", ""],
      ["a Bearer scheme without a value", "Bearer"],
      ["an undecodable Basic credential", "Basic !!!"],
    ])(
      "a header that is %s is 401, never the consumer: nothing gated, verified or resolved",
      async (_title, header) => {
        await listenTrusted();

        const reply = await send({ "proxy-authorization": header, "x-api-key": "harpoc:api-key" });

        expect(reply.status).toBe(401);
        expect(reply.headers["www-authenticate"]).toBe('Bearer realm="harpoc"');
        expect(JSON.parse(reply.body)).toEqual(MALFORMED);
        expect(double.assertProxyConsumer).not.toHaveBeenCalled();
        expect(double.verifyToken).not.toHaveBeenCalled();
        expect(double.resolveForProxy).not.toHaveBeenCalled();
        expect(upstream.seen).toHaveLength(0);
      },
    );

    it("a header past node's default cap of 1000 fields is still read: 401, never the consumer", async () => {
      await listenTrusted();
      const padding = Array.from({ length: 1000 }, (_, i) => `p${String(i)}: a\r\n`).join("");

      const answer = await rawSocketExchange(
        path,
        `GET /127.0.0.1:${upstream.port}/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n${padding}Proxy-Authorization: Bearer\r\nx-api-key: harpoc:api-key\r\nConnection: close\r\n\r\n`,
      );

      expect(answer.split("\r\n")[0]).toBe("HTTP/1.1 401 Unauthorized");
      expect(double.assertProxyConsumer).not.toHaveBeenCalled();
      expect(double.resolveForProxy).not.toHaveBeenCalled();
      expect(upstream.seen).toHaveLength(0);
    });

    it("a revoked token is 401 TOKEN_REVOKED, never the consumer: nothing gated or resolved", async () => {
      await listenTrusted();

      const reply = await send({
        "proxy-authorization": `Bearer ${TOKENS.revoked}`,
        "x-api-key": "harpoc:api-key",
      });

      expect(reply.status).toBe(401);
      expect(JSON.parse(reply.body)).toMatchObject({ error: ErrorCode.TOKEN_REVOKED });
      expect(double.assertProxyConsumer).not.toHaveBeenCalled();
      expect(double.resolveForProxy).not.toHaveBeenCalled();
      expect(upstream.seen).toHaveLength(0);
    });

    it("a tunnel a valid token opened by CONNECT with a CA: the request inside it, which carries no Proxy-Authorization, is the token's — never gated, no tokenless mark", async () => {
      await proxy.close();
      const hosts = ["127.0.0.1"];
      const ca = createCa({ permittedHosts: hosts, validityDays: 30 });
      proxy = createEgressProxy({
        engine: double.engine,
        refusalBudget: budget,
        ca: { certPem: ca.certPem, keyPem: ca.keyPem, hosts },
      });
      await listenTrusted();
      const tunnel = await openTunnel({
        socketPath: path,
        authority: `127.0.0.1:${upstream.port}`,
        fields: [`Proxy-Authorization: Bearer ${TOKENS.use}`],
        ca: ca.rootPem,
      });
      expect(tunnel.established).toBe("HTTP/1.1 200 Connection Established");

      const answer = await exchangeInTunnel(
        tunnel.socket as TLSSocket,
        `GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:${upstream.port}\r\nx-api-key: harpoc:api-key\r\nConnection: close\r\n\r\n`,
      );

      expect(answer.startsWith("HTTP/1.1 200 ")).toBe(true);
      expect(upstream.seen).toHaveLength(1);
      expect(upstream.seen[0]?.headers["x-api-key"]).toBe(SECRET_VALUE);
      expect(double.verifyToken).toHaveBeenCalledTimes(2);
      expect(double.verifyToken.mock.calls.every(([token]) => token === TOKENS.use)).toBe(true);
      expect(double.assertProxyConsumer).not.toHaveBeenCalled();
      const caller = double.resolveForProxy.mock.calls[0]?.[1];
      expect(caller).toEqual({
        principal_type: "agent",
        principal_id: "agent-a",
        interface: "proxy",
      });
      expect("tokenless" in (caller as object)).toBe(false);
    });
  });

  describe("the engine's gate on every tokenless request", () => {
    it.each([
      [ErrorCode.AGENT_INACTIVE, 403, VaultError.agentInactive(CONSUMER)],
      [ErrorCode.AGENT_NOT_FOUND, 404, VaultError.agentNotFound(CONSUMER)],
    ])(
      "%s is answered %i after one access.denied row naming the request and one charge; nothing resolved",
      async (code, status, refusal) => {
        await listenTrusted();
        double.assertProxyConsumer.mockImplementation(() => {
          throw refusal;
        });

        const reply = await send({ "x-api-key": "harpoc:api-key" });

        expect(reply.status).toBe(status);
        expect(JSON.parse(reply.body)).toMatchObject({ error: code });
        expect(double.auditProxyRefusal).toHaveBeenCalledTimes(1);
        expect(double.auditProxyRefusal).toHaveBeenCalledWith(
          TRUSTED,
          `POST ${upstream.origin}`,
          code,
        );
        expect(charge).toHaveBeenCalledTimes(1);
        expect(charge).toHaveBeenCalledWith(BUDGET_KEY);
        expect(double.resolveForProxy).not.toHaveBeenCalled();
        expect(upstream.seen).toHaveLength(0);
      },
    );

    it("VAULT_LOCKED is answered 503 with no refusal row and no charge", async () => {
      await listenTrusted();
      double.assertProxyConsumer.mockImplementation(() => {
        throw VaultError.vaultLocked();
      });

      const reply = await send({ "x-api-key": "harpoc:api-key" });

      expect(reply.status).toBe(503);
      expect(JSON.parse(reply.body)).toEqual({
        error: ErrorCode.VAULT_LOCKED,
        message: "Vault is locked",
      });
      expect(double.auditProxyRefusal).not.toHaveBeenCalled();
      expect(charge).not.toHaveBeenCalled();
      expect(double.resolveForProxy).not.toHaveBeenCalled();
      expect(upstream.seen).toHaveLength(0);
    });

    it("a pass-through (no placeholder) meets the same gate: 403 AGENT_INACTIVE, one row, one charge, nothing upstream", async () => {
      await listenTrusted();
      double.assertProxyConsumer.mockImplementation(() => {
        throw VaultError.agentInactive(CONSUMER);
      });

      const reply = await send({}, { method: "GET", target: `/127.0.0.1:${upstream.port}/plain` });

      expect(reply.status).toBe(403);
      expect(JSON.parse(reply.body)).toMatchObject({ error: ErrorCode.AGENT_INACTIVE });
      expect(double.assertProxyConsumer).toHaveBeenCalledWith(TRUSTED);
      expect(double.auditProxyRefusal).toHaveBeenCalledTimes(1);
      expect(double.auditProxyRefusal).toHaveBeenCalledWith(
        TRUSTED,
        `GET ${upstream.origin}`,
        ErrorCode.AGENT_INACTIVE,
      );
      expect(charge).toHaveBeenCalledTimes(1);
      expect(upstream.seen).toHaveLength(0);
    });

    it("a malformed target is 400 before the gate: nothing gated, no row, no charge", async () => {
      await listenTrusted();

      const reply = await send({}, { method: "GET", target: "/" });

      expect(reply.status).toBe(400);
      expect(JSON.parse(reply.body)).toMatchObject({ error: ErrorCode.INVALID_INPUT });
      expect(double.assertProxyConsumer).not.toHaveBeenCalled();
      expect(double.auditProxyRefusal).not.toHaveBeenCalled();
      expect(charge).not.toHaveBeenCalled();
    });

    it("two requests on one keep-alive connection: the agent deactivated while the first streams ends it as it would have, the second is 403 after one row", async () => {
      await listenTrusted();
      upstream.script((_req, res) => {
        res.writeHead(200, { "content-type": "text/plain" });
        res.write("first half ");
        double.assertProxyConsumer.mockImplementation(() => {
          throw VaultError.agentInactive(CONSUMER);
        });
        res.end("second half");
      });
      const agent = new Agent({ keepAlive: true, maxSockets: 1 });
      const target = `/127.0.0.1:${upstream.port}/v1/messages`;
      const headers = { "x-api-key": "harpoc:api-key" };
      let first: KeptReply;
      let second: KeptReply;
      try {
        first = await keptAliveRequest(agent, path, target, headers);
        second = await keptAliveRequest(agent, path, target, headers);
      } finally {
        agent.destroy();
      }

      expect(first.status).toBe(200);
      expect(first.body).toBe("first half second half");
      expect(double.leases[0]?.complete).toHaveBeenCalledWith({ status: 200, sanitized: false });
      expect(second.reused).toBe(true);
      expect(second.status).toBe(403);
      expect(JSON.parse(second.body)).toMatchObject({ error: ErrorCode.AGENT_INACTIVE });
      expect(double.assertProxyConsumer).toHaveBeenCalledTimes(2);
      expect(double.auditProxyRefusal).toHaveBeenCalledTimes(1);
      expect(double.auditProxyRefusal).toHaveBeenCalledWith(
        TRUSTED,
        `GET ${upstream.origin}`,
        ErrorCode.AGENT_INACTIVE,
      );
      expect(double.resolveForProxy).toHaveBeenCalledTimes(1);
      expect(upstream.seen).toHaveLength(1);
    });

    it("the budget the gate's refusals spend is checked ahead of the gate: the next request is 429 with no further gate call, row or charge", async () => {
      await listenTrusted();
      double.assertProxyConsumer.mockImplementation(() => {
        throw VaultError.agentInactive(CONSUMER);
      });
      const statuses: number[] = [];
      for (let i = 0; i < RATE_LIMIT_PROXY_REFUSALS; i++) {
        statuses.push((await send({ "x-api-key": "harpoc:api-key" })).status);
      }
      expect(statuses).toEqual(Array.from({ length: RATE_LIMIT_PROXY_REFUSALS }, () => 403));

      const next = await send({ "x-api-key": "harpoc:api-key" });

      expect(next.status).toBe(429);
      expect(JSON.parse(next.body)).toEqual(SPENT);
      expect(double.assertProxyConsumer).toHaveBeenCalledTimes(RATE_LIMIT_PROXY_REFUSALS);
      expect(charge).toHaveBeenCalledTimes(RATE_LIMIT_PROXY_REFUSALS);
      expect(double.auditProxyRefusal).toHaveBeenCalledTimes(RATE_LIMIT_PROXY_REFUSALS + 1);
      expect(double.auditProxyRefusal).toHaveBeenLastCalledWith(
        TRUSTED,
        "proxy refusal budget",
        ErrorCode.RATE_LIMIT_EXCEEDED,
      );
      expect(double.resolveForProxy).not.toHaveBeenCalled();
      expect(upstream.seen).toHaveLength(0);
    });

    describe.skipIf(!CAN_SET_DEFAULT_CA)(
      "a pass-through it admits (the fixture CA trusted by default)",
      () => {
        let restore: () => void;

        beforeAll(() => {
          restore = trustFixtureCaByDefault();
        });

        afterAll(() => {
          restore();
        });

        it("is served after one gate call: no refusal row, no charge, nothing resolved, the upstream's answer relayed", async () => {
          await listenTrusted();

          const reply = await send(
            {},
            { method: "GET", target: `/127.0.0.1:${upstream.port}/plain` },
          );

          expect(reply.status).toBe(200);
          expect(reply.body).toBe("ok");
          expect(upstream.seen).toHaveLength(1);
          expect(upstream.seen[0]?.url).toBe("/plain");
          expect(double.assertProxyConsumer).toHaveBeenCalledTimes(1);
          expect(double.assertProxyConsumer).toHaveBeenCalledWith(TRUSTED);
          expect(double.auditProxyRefusal).not.toHaveBeenCalled();
          expect(double.auditScopeRefusal).not.toHaveBeenCalled();
          expect(charge).not.toHaveBeenCalled();
          expect(double.resolveForProxy).not.toHaveBeenCalled();
        });
      },
    );
  });

  describe("the secret-name patterns", () => {
    it("a handle outside them is 403 ACCESS_DENIED after one scope refusal row and one charge; nothing resolved", async () => {
      await listenTrusted();

      const reply = await send({ "x-api-key": "harpoc:other-key" });

      expect(reply.status).toBe(403);
      expect(JSON.parse(reply.body)).toEqual(NOT_SERVED);
      expect(double.assertProxyConsumer).toHaveBeenCalledTimes(1);
      expect(double.auditScopeRefusal).toHaveBeenCalledTimes(1);
      expect(double.auditScopeRefusal).toHaveBeenCalledWith(
        TRUSTED,
        `POST ${upstream.origin}/v1/messages`,
        "secret",
      );
      expect(charge).toHaveBeenCalledTimes(1);
      expect(charge).toHaveBeenCalledWith(BUDGET_KEY);
      expect(double.auditProxyRefusal).not.toHaveBeenCalled();
      expect(double.resolveForProxy).not.toHaveBeenCalled();
      expect(upstream.seen).toHaveLength(0);
    });
  });

  it("a CONNECT without Proxy-Authorization is 407 on a trusted socket with a CA; nothing gated or verified", async () => {
    await proxy.close();
    const hosts = ["example.com"];
    const ca = createCa({ permittedHosts: hosts, validityDays: 30 });
    proxy = createEgressProxy({
      engine: double.engine,
      refusalBudget: budget,
      ca: { certPem: ca.certPem, keyPem: ca.keyPem, hosts },
    });
    await listenTrusted();

    const answer = await rawSocketExchange(
      path,
      "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
    );

    const lines = answer.slice(0, answer.indexOf("\r\n\r\n")).split("\r\n");
    expect(lines[0]).toBe("HTTP/1.1 407 Proxy Authentication Required");
    expect(lines.filter((line) => line.startsWith("proxy-authenticate: "))).toEqual([
      'proxy-authenticate: Basic realm="harpoc"',
      'proxy-authenticate: Bearer realm="harpoc"',
    ]);
    expect(double.assertProxyConsumer).not.toHaveBeenCalled();
    expect(double.verifyToken).not.toHaveBeenCalled();
  });

  describe("listenTrustedSocket", () => {
    it("binds mode 0660 and writes exactly one server.start row naming the consumer", async () => {
      await listenTrusted();

      expect(lstatSync(path).isSocket()).toBe(true);
      expect(statSync(path).mode & 0o777).toBe(0o660);
      expect(double.auditServerStart).toHaveBeenCalledTimes(1);
      expect(double.auditServerStart).toHaveBeenCalledWith({
        transport: "proxy",
        tokenless: true,
        consumer: "agent1",
      });
    });

    it("an unwritable start row is the refusal and undoes the bind: nothing accepts, no file is left", async () => {
      double.auditServerStart.mockImplementationOnce(() => {
        throw VaultError.vaultLocked();
      });

      await expectVaultError(() => listenTrusted(), ErrorCode.VAULT_LOCKED);

      expect(await socketAccepts(path)).toBe(false);
      expect(existsSync(path)).toBe(false);
    });

    it("unlinks a stale socket file nothing accepts on, then binds", async () => {
      // A listener SIGKILLed after its bind leaves its socket file behind.
      const child = spawn(
        process.execPath,
        [
          "-e",
          `require("net").createServer().listen(${JSON.stringify(path)}, () => process.kill(process.pid, "SIGKILL"))`,
        ],
        { stdio: "ignore" },
      );
      const deadline = setTimeout(() => child.kill("SIGKILL"), PROXY_CLIENT_TIMEOUT_MS);
      await new Promise<void>((resolve) => child.on("close", () => resolve()));
      clearTimeout(deadline);
      expect(lstatSync(path).isSocket()).toBe(true);

      await listenTrusted();

      expect(statSync(path).mode & 0o777).toBe(0o660);
      expect(await socketAccepts(path)).toBe(true);
      expect(double.auditServerStart).toHaveBeenCalledTimes(1);
    });

    it("refuses a path that is a regular file as listenSocket does, leaves it untouched and writes no row", async () => {
      writeFileSync(path, "not a socket");

      const err = await expectVaultError(() => listenTrusted(), ErrorCode.INVALID_INPUT);

      expect(err.message).toBe(`Egress proxy socket: ${path} exists and is not a socket`);
      expect(readFileSync(path, "utf8")).toBe("not a socket");
      expect(double.auditServerStart).not.toHaveBeenCalled();
    });

    it("close() removes the trusted socket's file", async () => {
      await listenTrusted();
      await proxy.close();

      expect(existsSync(path)).toBe(false);
    });

    it("refuses an empty list of secret-name patterns INVALID_INPUT before the bind: no file, no row", async () => {
      const err = await expectVaultError(
        () => proxy.listenTrustedSocket(path, CONSUMER, []),
        ErrorCode.INVALID_INPUT,
      );

      expect(err.message).toBe(
        `Egress proxy socket: a trusted socket needs at least one secret-name pattern: ${path}`,
      );
      expect(existsSync(path)).toBe(false);
      expect(double.auditServerStart).not.toHaveBeenCalled();
    });

    it("refuses on a proxy that is closed INVALID_INPUT: no file, no row", async () => {
      await proxy.close();

      const err = await expectVaultError(() => listenTrusted(), ErrorCode.INVALID_INPUT);

      expect(err.message).toBe(`Egress proxy socket: the proxy is closed: ${path}`);
      expect(await socketAccepts(path)).toBe(false);
      expect(existsSync(path)).toBe(false);
      expect(double.auditServerStart).not.toHaveBeenCalled();
    });

    it("on a proxy that is closed the ladder is not entered: a regular file at the path is refused as closed and left untouched", async () => {
      writeFileSync(path, "not a socket");
      await proxy.close();

      const err = await expectVaultError(() => listenTrusted(), ErrorCode.INVALID_INPUT);

      expect(err.message).toBe(`Egress proxy socket: the proxy is closed: ${path}`);
      expect(readFileSync(path, "utf8")).toBe("not a socket");
      expect(double.auditServerStart).not.toHaveBeenCalled();
    });

    it("a close() that lands while it binds undoes the bind: INVALID_INPUT, nothing accepts, no file, no row", async () => {
      const refused = expectVaultError(() => listenTrusted(), ErrorCode.INVALID_INPUT);
      await proxy.close();

      const err = await refused;

      expect(err.message).toBe(`Egress proxy socket: the proxy is closed: ${path}`);
      expect(await socketAccepts(path)).toBe(false);
      expect(existsSync(path)).toBe(false);
      expect(double.auditServerStart).not.toHaveBeenCalled();
    });

    it("listenSocket after close() is unchanged: it binds proxy.sock, which accepts, with no row of its own", async () => {
      const plain = join(dir, "proxy.sock");
      await proxy.close();

      await proxy.listenSocket(plain);

      expect(await socketAccepts(plain)).toBe(true);
      expect(double.auditServerStart).not.toHaveBeenCalled();
    });
  });
});
