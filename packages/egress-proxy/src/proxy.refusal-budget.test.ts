import type { TLSSocket } from "node:tls";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createCa } from "@harpoc/cert-manager";
import { ErrorCode, TokenPrincipalType, VaultError } from "@harpoc/shared";
import type { VaultApiToken } from "@harpoc/shared";
import type { ProxyCaOptions } from "./ca.js";
import type { EgressProxy } from "./proxy.js";
import { createEgressProxy } from "./proxy.js";
import { RefusalBudget, refusalBudgetKey } from "./refusal-budget.js";
import { TOKENS, engineDouble } from "./__fixtures__/engine-double.js";
import type { EngineDouble } from "./__fixtures__/engine-double.js";
import { proxyRequest } from "./__fixtures__/proxy-client.js";
import type { ProxyReply } from "./__fixtures__/proxy-client.js";
import { exchangeInTunnel, openTunnel } from "./__fixtures__/tunnel-client.js";
import type { TunnelOpen } from "./__fixtures__/tunnel-client.js";
import { deadPort, startUpstream } from "./__fixtures__/upstream-server.js";
import type { UpstreamFixture } from "./__fixtures__/upstream-server.js";

const HOSTS = ["127.0.0.1"];
const CA = createCa({ permittedHosts: HOSTS, validityDays: 30 });
const CA_OPTIONS: ProxyCaOptions = { certPem: CA.certPem, keyPem: CA.keyPem, hosts: HOSTS };
const LIMITED_HANDLE = "secret://limited";
const OTHER_TOKEN = "tok-other";
const SPENT = { error: ErrorCode.RATE_LIMIT_EXCEEDED, message: "Proxy refusal budget exceeded" };
const KEY = refusalBudgetKey({ principal_type: TokenPrincipalType.AGENT, principal_id: "agent-a" });
const EVIL = "evil.example:443";
const REFUSED = ["a.example:443", "b.example:443", "c.example:443"];

let upstream: UpstreamFixture;
let dead: number;
let double: EngineDouble;
let proxy: EgressProxy;
let port: number;
let clock: number;
let budget: RefusalBudget;
let reports: [string, number][];

beforeAll(async () => {
  upstream = await startUpstream();
  dead = await deadPort();
});

afterAll(async () => {
  await upstream.close();
});

beforeEach(async () => {
  upstream.seen.length = 0;
  clock = 0;
  double = engineDouble();
  budget = new RefusalBudget(3, 60_000, () => clock);
  reports = [];
  proxy = createEgressProxy({
    engine: double.engine,
    ca: CA_OPTIONS,
    rateLimiter: {
      checkSecret: (handle) => {
        if (handle === LIMITED_HANDLE) {
          throw new VaultError(ErrorCode.RATE_LIMIT_EXCEEDED, "Per-secret rate limit exceeded");
        }
      },
    },
    refusalBudget: budget,
    onError: (err, status) => reports.push([err.code, status]),
  });
  port = (await proxy.listenTcp(0, "127.0.0.1")).port;
});

afterEach(async () => {
  await proxy.close();
});

function send(
  target: string,
  headers: Record<string, string> = {},
  token: string | null = TOKENS.use,
): Promise<ProxyReply> {
  return proxyRequest({
    port,
    path: target,
    headers: {
      ...(token === null ? {} : { "proxy-authorization": `Bearer ${token}` }),
      ...headers,
    },
  });
}

const brokered = (handle = "gh-pat", token: string | null = TOKENS.use): Promise<ProxyReply> =>
  send(`/127.0.0.1:${upstream.port}/user`, { authorization: `Bearer harpoc:${handle}` }, token);

const scopeRefusal = (): Promise<ProxyReply> => brokered("gh-pat", TOKENS.read);

const twoPlaceholders = (): Promise<ProxyReply> =>
  send(`/127.0.0.1:${upstream.port}/q?token=harpoc:other`, {
    authorization: "Bearer harpoc:gh-pat",
  });

const connectTo = (authority: string): Promise<TunnelOpen> =>
  openTunnel({
    port,
    authority,
    fields: [`Proxy-Authorization: Bearer ${TOKENS.use}`],
    ca: CA.rootPem,
  });

async function spend(): Promise<void> {
  const statuses: number[] = [];
  for (let i = 0; i < 3; i++) statuses.push((await scopeRefusal()).status);
  expect(statuses).toEqual([403, 403, 403]);
}

const statusLine = (answer: TunnelOpen): string | undefined => answer.established.split("\r\n")[0];

const rows = (): [string, ErrorCode][] =>
  double.auditProxyRefusal.mock.calls.map(([, operation, code]): [string, ErrorCode] => [
    operation,
    code,
  ]);

describe("the refusal budget — checked after authentication, charged by every refusal that leaves a row", () => {
  it("the third scope refusal is answered 403 and writes the trip row", async () => {
    await spend();

    expect(double.auditScopeRefusal).toHaveBeenCalledTimes(3);
    expect(double.auditProxyRefusal).toHaveBeenCalledTimes(1);
    expect(double.auditProxyRefusal).toHaveBeenCalledWith(
      expect.objectContaining({ principal_id: "agent-a", interface: "proxy" }),
      "proxy refusal budget",
      ErrorCode.RATE_LIMIT_EXCEEDED,
    );
    const next = await scopeRefusal();
    expect(next.status).toBe(429);
    expect(JSON.parse(next.body)).toEqual(SPENT);
    expect(double.auditScopeRefusal).toHaveBeenCalledTimes(3);
  });

  it("a spent principal gets 429 on a request that would have passed", async () => {
    await spend();

    const passThrough = await send(`/127.0.0.1:${upstream.port}/plain`);
    const withPlaceholder = await brokered();

    expect(passThrough.status).toBe(429);
    expect(JSON.parse(passThrough.body)).toEqual(SPENT);
    expect(withPlaceholder.status).toBe(429);
    expect(JSON.parse(withPlaceholder.body)).toEqual(SPENT);
    expect(upstream.seen).toHaveLength(0);
    expect(double.resolveForProxy).not.toHaveBeenCalled();
    expect(double.auditProxyRefusal).toHaveBeenCalledTimes(1);
  });

  it("a spent principal gets 429 on a CONNECT before the host is judged", async () => {
    await spend();

    const answer = await connectTo("evil.example:443");

    expect(answer.established.startsWith("HTTP/1.1 429 Too Many Requests\r\n")).toBe(true);
    expect(answer.socket).toBeUndefined();
    expect(JSON.parse(answer.body ?? "")).toEqual(SPENT);
    expect(double.auditProxyRefusal).toHaveBeenCalledTimes(1);
    expect(double.auditProxyRefusal).toHaveBeenCalledWith(
      expect.anything(),
      "proxy refusal budget",
      ErrorCode.RATE_LIMIT_EXCEEDED,
    );
  });

  it("a spent principal gets 429 on a request inside a tunnel opened before the trip", async () => {
    const tunnel = await connectTo(`127.0.0.1:${upstream.port}`);
    expect(tunnel.established).toBe("HTTP/1.1 200 Connection Established");
    await spend();

    const answer = await exchangeInTunnel(
      tunnel.socket as TLSSocket,
      `GET /user HTTP/1.1\r\nHost: 127.0.0.1:${upstream.port}\r\nAuthorization: Bearer harpoc:gh-pat\r\nConnection: close\r\n\r\n`,
    );

    expect(answer.startsWith("HTTP/1.1 429 ")).toBe(true);
    expect(answer).toContain(JSON.stringify(SPENT));
    expect(upstream.seen).toHaveLength(0);
    expect(double.resolveForProxy).not.toHaveBeenCalled();
  });

  it("unknown handles spend the budget", async () => {
    double.resolveForProxy.mockImplementation(async (handle) => {
      throw new VaultError(ErrorCode.SECRET_NOT_FOUND, `Secret not found: ${handle}`);
    });

    const statuses: number[] = [];
    for (const handle of ["one", "two", "three"]) statuses.push((await brokered(handle)).status);
    const fourth = await brokered("four");

    expect(statuses).toEqual([404, 404, 404]);
    expect(fourth.status).toBe(429);
    expect(JSON.parse(fourth.body)).toEqual(SPENT);
    expect(double.resolveForProxy).toHaveBeenCalledTimes(3);
    expect(double.auditProxyRefusal).toHaveBeenCalledTimes(1);
    expect(double.auditProxyRefusal).toHaveBeenCalledWith(
      expect.objectContaining({ principal_id: "agent-a" }),
      "proxy refusal budget",
      ErrorCode.RATE_LIMIT_EXCEEDED,
    );
  });

  it("the three new refusals each charge", async () => {
    const refusedConnect = await connectTo("evil.example:443");
    const refusedPlaceholders = await twoPlaceholders();
    const refusedPassThrough = await send("/10.0.0.1/x");
    const next = await brokered();

    expect(refusedConnect.established.startsWith("HTTP/1.1 403 ")).toBe(true);
    expect(refusedPlaceholders.status).toBe(403);
    expect(refusedPassThrough.status).toBe(403);
    expect(next.status).toBe(429);
    expect(JSON.parse(next.body)).toEqual(SPENT);
    expect(
      double.auditProxyRefusal.mock.calls.map(([, operation, code]) => [operation, code]),
    ).toEqual([
      ["CONNECT evil.example:443", ErrorCode.PROXY_CONNECT_DENIED],
      [`GET ${upstream.origin}`, ErrorCode.PROXY_PLACEHOLDER_DENIED],
      ["GET https://10.0.0.1", ErrorCode.SSRF_BLOCKED],
      ["proxy refusal budget", ErrorCode.RATE_LIMIT_EXCEEDED],
    ]);
  });

  it.each<[string, number, () => Promise<ProxyReply>]>([
    ["a success", 200, () => brokered()],
    ["a per-handle 429", 429, () => brokered("limited")],
    ["a 407", 407, () => brokered("gh-pat", null)],
    [
      "a VAULT_LOCKED from resolveForProxy",
      503,
      () => {
        double.resolveForProxy.mockRejectedValueOnce(VaultError.vaultLocked());
        return brokered();
      },
    ],
    [
      "an INVALID_INPUT from resolveForProxy",
      400,
      () => {
        double.resolveForProxy.mockRejectedValueOnce(
          VaultError.invalidInput("Invalid proxy target"),
        );
        return brokered();
      },
    ],
    [
      "an OAUTH_REFRESH_FAILED from resolveForProxy",
      502,
      () => {
        double.resolveForProxy.mockRejectedValueOnce(
          VaultError.oauthRefreshFailed("the provider answered 503"),
        );
        return brokered();
      },
    ],
    [
      "a 502 after the lease",
      502,
      () => send(`/127.0.0.1:${dead}/x`, { authorization: "Bearer harpoc:gh-pat" }),
    ],
    [
      "a refusal after the lease (the address check on a brokered request)",
      403,
      () => send("/10.0.0.1/x", { authorization: "Bearer harpoc:gh-pat" }),
    ],
  ])("what does not charge the budget: %s, sent four times", async (_title, status, request) => {
    const statuses: number[] = [];
    for (let i = 0; i < 4; i++) statuses.push((await request()).status);
    const further = await brokered();

    expect(statuses).toEqual([status, status, status, status]);
    expect(further.status).toBe(200);
    expect(double.auditProxyRefusal).not.toHaveBeenCalled();
  });

  it("another principal is served while one is spent", async () => {
    const verify = double.verifyToken.getMockImplementation() as (token: string) => VaultApiToken;
    double.verifyToken.mockImplementation((token) =>
      token === OTHER_TOKEN ? { ...verify(TOKENS.use), sub: "agent-b" } : verify(token),
    );
    await spend();

    const other = await brokered("gh-pat", OTHER_TOKEN);
    const spent = await brokered();

    expect(other.status).toBe(200);
    expect(spent.status).toBe(429);
  });

  it("the window ends", async () => {
    await spend();
    expect((await brokered()).status).toBe(429);

    clock += 60_000;

    expect((await brokered()).status).toBe(200);
  });

  it.each<[string, number, () => Promise<ProxyReply>]>([
    ["a scope refusal", 403, scopeRefusal],
    ["a two-placeholder refusal", 403, twoPlaceholders],
    [
      "an unknown handle",
      404,
      () => {
        double.resolveForProxy.mockRejectedValueOnce(
          new VaultError(ErrorCode.SECRET_NOT_FOUND, "Secret not found: secret://gh-pat"),
        );
        return brokered();
      },
    ],
  ])(
    "a trip row that cannot be written answers 503 in place of the third refusal: %s",
    async (_title, status, request) => {
      double.auditProxyRefusal.mockImplementation((_caller, operation) => {
        if (operation === "proxy refusal budget") throw VaultError.vaultLocked();
      });

      const statuses: number[] = [];
      for (let i = 0; i < 2; i++) statuses.push((await request()).status);
      const third = await request();

      expect(statuses).toEqual([status, status]);
      expect(third.status).toBe(503);
      expect(JSON.parse(third.body)).toEqual({
        error: ErrorCode.VAULT_LOCKED,
        message: "Vault is locked",
      });
    },
  );
});

describe("the refusal budget — a refused CONNECT host costs once per window, the trip is reported once", () => {
  it("sixty refused CONNECTs to one host cost one row and one charge", async () => {
    const charge = vi.spyOn(budget, "charge");

    const answers: TunnelOpen[] = [];
    for (let i = 0; i < 4; i++) answers.push(await connectTo(EVIL));

    const first = answers[0] as TunnelOpen;
    expect(statusLine(first)).toBe("HTTP/1.1 403 Forbidden");
    expect(JSON.parse(first.body ?? "")).toMatchObject({ error: ErrorCode.PROXY_CONNECT_DENIED });
    expect(answers.map((answer) => `${answer.established}\r\n\r\n${answer.body ?? ""}`)).toEqual(
      Array.from({ length: 4 }, () => `${first.established}\r\n\r\n${first.body ?? ""}`),
    );
    expect(rows()).toEqual([[`CONNECT ${EVIL}`, ErrorCode.PROXY_CONNECT_DENIED]]);
    expect(charge).toHaveBeenCalledTimes(1);
    expect(budget.spent(KEY)).toBe(false);
    expect(reports).toEqual([[ErrorCode.PROXY_CONNECT_DENIED, 403]]);
  });

  it("refused CONNECTs to as many hosts as the limit trip the budget", async () => {
    const answers: TunnelOpen[] = [];
    for (const authority of REFUSED) answers.push(await connectTo(authority));
    const next = await connectTo("d.example:443");

    expect(answers.map(statusLine)).toEqual(
      Array.from({ length: 3 }, () => "HTTP/1.1 403 Forbidden"),
    );
    expect(rows()).toEqual([
      ...REFUSED.map((authority) => [`CONNECT ${authority}`, ErrorCode.PROXY_CONNECT_DENIED]),
      ["proxy refusal budget", ErrorCode.RATE_LIMIT_EXCEEDED],
    ]);
    expect(statusLine(next)).toBe("HTTP/1.1 429 Too Many Requests");
    expect(JSON.parse(next.body ?? "")).toEqual(SPENT);
  });

  it("the trip is reported once and the 429s after it are not", async () => {
    for (const authority of REFUSED) await connectTo(authority);
    expect(reports).toEqual([
      [ErrorCode.PROXY_CONNECT_DENIED, 403],
      [ErrorCode.PROXY_CONNECT_DENIED, 403],
      [ErrorCode.RATE_LIMIT_EXCEEDED, 429],
      [ErrorCode.PROXY_CONNECT_DENIED, 403],
    ]);

    const after: (string | number | undefined)[] = [];
    for (let i = 0; i < 5; i++) {
      after.push(statusLine(await connectTo(i % 2 === 0 ? EVIL : (REFUSED[0] as string))));
      after.push((await brokered()).status);
    }

    expect(after).toEqual(
      Array.from({ length: 5 }, () => ["HTTP/1.1 429 Too Many Requests", 429]).flat(),
    );
    expect(reports).toHaveLength(4);
    expect(double.auditProxyRefusal).toHaveBeenCalledTimes(4);
  });

  it("the per-handle limiter's 429 is still reported", async () => {
    const answer = await brokered("limited");

    expect(answer.status).toBe(429);
    expect(JSON.parse(answer.body)).toEqual({
      error: ErrorCode.RATE_LIMIT_EXCEEDED,
      message: "Per-secret rate limit exceeded",
    });
    expect(reports).toEqual([[ErrorCode.RATE_LIMIT_EXCEEDED, 429]]);
  });

  it("a CONNECT refusal whose row cannot be written is not remembered", async () => {
    const opening = await scopeRefusal();
    expect(opening.status).toBe(403);
    double.auditProxyRefusal.mockImplementationOnce(() => {
      throw VaultError.vaultLocked();
    });

    const failed = await connectTo(EVIL);
    const retried = await connectTo(EVIL);
    const repeated = await connectTo(EVIL);

    expect([failed, retried, repeated].map(statusLine)).toEqual([
      "HTTP/1.1 503 Service Unavailable",
      "HTTP/1.1 403 Forbidden",
      "HTTP/1.1 403 Forbidden",
    ]);
    expect(rows()).toEqual([
      [`CONNECT ${EVIL}`, ErrorCode.PROXY_CONNECT_DENIED],
      [`CONNECT ${EVIL}`, ErrorCode.PROXY_CONNECT_DENIED],
    ]);
    expect(reports).toEqual([
      [ErrorCode.ACCESS_DENIED, 403],
      [ErrorCode.VAULT_LOCKED, 503],
      [ErrorCode.PROXY_CONNECT_DENIED, 403],
    ]);
  });

  it("the window ends and the host costs a row again", async () => {
    const inWindow = [await connectTo(EVIL), await connectTo(EVIL)];
    expect(inWindow.map(statusLine)).toEqual(["HTTP/1.1 403 Forbidden", "HTTP/1.1 403 Forbidden"]);
    expect(double.auditProxyRefusal).toHaveBeenCalledTimes(1);

    clock += 60_000;
    const again = await connectTo(EVIL);

    expect(statusLine(again)).toBe("HTTP/1.1 403 Forbidden");
    expect(rows()).toEqual([
      [`CONNECT ${EVIL}`, ErrorCode.PROXY_CONNECT_DENIED],
      [`CONNECT ${EVIL}`, ErrorCode.PROXY_CONNECT_DENIED],
    ]);
    expect(reports).toEqual([
      [ErrorCode.PROXY_CONNECT_DENIED, 403],
      [ErrorCode.PROXY_CONNECT_DENIED, 403],
    ]);
  });

  it("a trip row that cannot be written reports nothing", async () => {
    double.auditProxyRefusal.mockImplementation((_caller, operation) => {
      if (operation === "proxy refusal budget") throw VaultError.vaultLocked();
    });

    const answers: TunnelOpen[] = [];
    for (const authority of REFUSED) answers.push(await connectTo(authority));

    expect(answers.map(statusLine)).toEqual([
      "HTTP/1.1 403 Forbidden",
      "HTTP/1.1 403 Forbidden",
      "HTTP/1.1 503 Service Unavailable",
    ]);
    expect(reports).toEqual([
      [ErrorCode.PROXY_CONNECT_DENIED, 403],
      [ErrorCode.PROXY_CONNECT_DENIED, 403],
      [ErrorCode.VAULT_LOCKED, 503],
    ]);
    expect(budget.spent(KEY)).toBe(true);
  });
});
