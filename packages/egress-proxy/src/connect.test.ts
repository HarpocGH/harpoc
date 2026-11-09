import { connect } from "node:net";
import type { TLSSocket } from "node:tls";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ProxyAgent, request } from "undici";
import { createCa } from "@harpoc/cert-manager";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { VaultApiToken } from "@harpoc/shared";
import type { ProxyCaOptions } from "./ca.js";
import { parseConnectTarget, tunnelTarget } from "./connect.js";
import type { Tunnel } from "./connect.js";
import type { EgressProxy, EgressProxyOptions } from "./proxy.js";
import { createEgressProxy } from "./proxy.js";
import { SECRET_VALUE, TOKENS, engineDouble } from "./__fixtures__/engine-double.js";
import type { EngineDouble } from "./__fixtures__/engine-double.js";
import { PROXY_CLIENT_TIMEOUT_MS } from "./__fixtures__/proxy-client.js";
import { exchangeInTunnel, openTunnel } from "./__fixtures__/tunnel-client.js";
import {
  CAN_SET_DEFAULT_CA,
  startUpstream,
  trustFixtureCaByDefault,
} from "./__fixtures__/upstream-server.js";
import type { UpstreamFixture } from "./__fixtures__/upstream-server.js";

const MARKER = "[REDACTED]";
const HOSTS = ["127.0.0.1", "localhost"];
const CA = createCa({ permittedHosts: HOSTS, validityDays: 30 });
/** The proxy signs with the intermediate and serves it after each leaf; the clients trust the root alone (R-X1). */
const CA_OPTIONS: ProxyCaOptions = { certPem: CA.certPem, keyPem: CA.keyPem, hosts: HOSTS };

let upstream: UpstreamFixture;
let double: EngineDouble;
let proxy: EgressProxy;
let port: number;
let errors: VaultError[];
const agents: ProxyAgent[] = [];

beforeAll(async () => {
  upstream = await startUpstream();
});

afterAll(async () => {
  await upstream.close();
});

async function startProxy(extra: Partial<EgressProxyOptions> = {}): Promise<void> {
  double = engineDouble();
  errors = [];
  proxy = createEgressProxy({
    engine: double.engine,
    ca: CA_OPTIONS,
    onError: (err) => errors.push(err),
    ...extra,
  });
  port = (await proxy.listenTcp(0, "127.0.0.1")).port;
}

beforeEach(async () => {
  upstream.seen.length = 0;
  upstream.script((req, res) => {
    res.writeHead(200, {
      "content-type": "application/json",
      "x-echo": req.headers.authorization ?? "",
    });
    res.end(JSON.stringify(req.headers));
  });
  await startProxy();
});

afterEach(async () => {
  vi.useRealTimers();
  await Promise.all(agents.splice(0).map((agent) => agent.destroy()));
  await proxy.close();
});

/** undici's ProxyAgent — the CONNECT carries `token` as its Proxy-Authorization; the tunnel's leaf verified against the CA. */
function agentWith(token: string | undefined = `Bearer ${TOKENS.use}`, uri?: string): ProxyAgent {
  const agent = new ProxyAgent({
    uri: uri ?? `http://127.0.0.1:${port}`,
    ...(token === undefined ? {} : { token }),
    requestTls: { ca: CA.rootPem },
  });
  agents.push(agent);
  return agent;
}

async function viaTunnel(
  dispatcher: ProxyAgent,
  path: string,
  headers: Record<string, string> = {},
): Promise<{ status: number; headers: Record<string, unknown>; body: string }> {
  const res = await request(`${upstream.origin}${path}`, {
    dispatcher,
    headers,
    headersTimeout: PROXY_CLIENT_TIMEOUT_MS,
  });
  return { status: res.statusCode, headers: res.headers, body: await res.body.text() };
}

const fields = (token: string = TOKENS.use): string[] => [`Proxy-Authorization: Bearer ${token}`];

/** One request line for a raw exchange inside the tunnel; the last of a pipelined series carries `Connection: close`. */
const line = (path: string, last = false): string =>
  `GET ${path} HTTP/1.1\r\nHost: 127.0.0.1:${upstream.port}\r\n` +
  `Authorization: Bearer harpoc:gh-pat\r\n${last ? "Connection: close\r\n" : ""}\r\n`;

async function tunnelToUpstream(): Promise<TLSSocket> {
  const tunnel = await openTunnel({
    port,
    authority: `127.0.0.1:${upstream.port}`,
    fields: fields(),
    ca: CA.rootPem,
  });
  return tunnel.socket as TLSSocket;
}

describe("parseConnectTarget — CONNECT <host>:<port> (RFC 9110 § 9.3.6)", () => {
  it.each([
    ["api.github.com:443", "api.github.com", 443, "api.github.com:443"],
    ["API.GitHub.com:8443", "api.github.com", 8443, "api.github.com:8443"],
    ["127.0.0.1:1", "127.0.0.1", 1, "127.0.0.1:1"],
    ["[::1]:443", "::1", 443, "[::1]:443"],
    ["[2001:DB8::1]:65535", "2001:db8::1", 65535, "[2001:db8::1]:65535"],
  ])("%s → host %s, port %i", (line, host, port, authority) => {
    expect(parseConnectTarget(line)).toStrictEqual({ ok: true, host, port, authority });
  });

  it.each([
    "api.github.com",
    "api.github.com:",
    "api.github.com:0",
    "api.github.com:65536",
    "api.github.com:443/x",
    "user@api.github.com:443",
    "::1:443",
    "[::g]:443",
    "localhost.:443",
    "",
  ])("not a CONNECT target: %j", (line) => {
    expect(parseConnectTarget(line)).toEqual({
      ok: false,
      message: "Not a CONNECT target: send CONNECT <host>:<port>",
    });
  });
});

describe("tunnelTarget — the request inside the tunnel", () => {
  const tunnel: Tunnel = {
    authority: "api.github.com:443",
    host: "api.github.com",
    port: 443,
    token: "t",
    peer: "127.0.0.1",
  };

  it("an origin-form path is appended to the tunnel's authority as a string; the form is absolute-https", () => {
    const parsed = tunnelTarget("//evil.example/x?q=1#f", tunnel);
    expect(parsed.ok && parsed.target.url.href).toBe("https://api.github.com//evil.example/x?q=1");
    expect(parsed.ok && parsed.target.form).toBe("absolute-https");
  });

  it("an absolute-form https line naming the tunnel's own authority is read as its path", () => {
    const parsed = tunnelTarget("https://API.github.com:443/user", tunnel);
    expect(parsed.ok && parsed.target.url.href).toBe("https://api.github.com/user");
  });

  it.each([
    "https://other.example/user",
    "https://api.github.com:8443/user",
    "http://api.github.com/user",
    "https://u:p@api.github.com/user",
    "*",
  ])("refused: %j", (line) => {
    expect(tunnelTarget(line, tunnel)).toMatchObject({ ok: false });
  });
});

describe("CONNECT — the tunnel", () => {
  it("a bearer placeholder through the tunnel is swapped upstream and redacted in the reply; one lease, the tunnel's origin judged", async () => {
    const reply = await viaTunnel(agentWith(), "/user?x=1", {
      authorization: "Bearer harpoc:gh-pat",
      "accept-encoding": "gzip",
    });

    expect(reply.status).toBe(200);
    expect(upstream.seen).toHaveLength(1);
    expect(upstream.seen[0]?.headers.authorization).toBe(`Bearer ${SECRET_VALUE}`);
    expect(upstream.seen[0]?.headers["proxy-authorization"]).toBeUndefined();
    expect(upstream.seen[0]?.headers["accept-encoding"]).toBe("identity");
    expect(reply.headers["x-echo"]).toBe(`Bearer ${MARKER}`);
    expect(reply.body).not.toContain(SECRET_VALUE);
    expect(double.resolveForProxy).toHaveBeenCalledWith(
      "secret://gh-pat",
      {
        principal_type: "agent",
        principal_id: "agent-a",
        interface: "proxy",
        remote_address: "127.0.0.1",
      },
      { method: "GET", origin: upstream.origin, path: "/user" },
    );
    await vi.waitFor(() => expect(double.leases[0]?.complete).toHaveBeenCalled());
    expect(double.leases[0]?.complete).toHaveBeenCalledTimes(1);
    expect(double.leases[0]?.complete).toHaveBeenCalledWith({ status: 200, sanitized: true });
  });

  it("Proxy-Authorization: Basic base64(<user>:<token>) — a proxy URL's userinfo — authenticates the CONNECT; the user is ignored", async () => {
    const reply = await viaTunnel(
      agentWith(undefined, `http://anyone:${TOKENS.use}@127.0.0.1:${port}`),
      "/user",
      { authorization: "Bearer harpoc:gh-pat" },
    );

    expect(reply.status).toBe(200);
    expect(double.verifyToken).toHaveBeenNthCalledWith(1, TOKENS.use);
  });

  it("the GitHub CLI's Authorization: token <placeholder> is swapped under its own scheme", async () => {
    const reply = await viaTunnel(agentWith(), "/api/v3/zen", {
      authorization: "token harpoc:gh-pat",
    });

    expect(reply.status).toBe(200);
    expect(upstream.seen[0]?.headers.authorization).toBe(`token ${SECRET_VALUE}`);
    expect(reply.headers["x-echo"]).toBe(`token ${MARKER}`);
  });

  it("keep-alive: pipelined requests ride one tunnel; the token is verified for the CONNECT and again for each request", async () => {
    const answer = await exchangeInTunnel(
      await tunnelToUpstream(),
      line("/one") + line("/two", true),
    );

    expect(answer.match(/HTTP\/1\.1 200 OK/g)).toHaveLength(2);
    expect(upstream.seen.map((seen) => seen.url)).toEqual(["/one", "/two"]);
    expect(double.verifyToken).toHaveBeenCalledTimes(3);
    expect(double.verifyToken.mock.calls.every(([token]) => token === TOKENS.use)).toBe(true);
  });

  it("a token revoked mid-tunnel: the next request is 401 TOKEN_REVOKED with connection: close, the tunnel ends, nothing more upstream", async () => {
    const verify = double.verifyToken.getMockImplementation() as (token: string) => VaultApiToken;
    double.verifyToken.mockImplementation((token) => {
      if (double.verifyToken.mock.calls.length > 2) throw VaultError.tokenRevoked();
      return verify(token);
    });
    const answer = await exchangeInTunnel(
      await tunnelToUpstream(),
      line("/one") + line("/two") + line("/three", true),
    );

    const replies = answer.split(/(?=HTTP\/1\.1 )/);
    expect(replies).toHaveLength(2);
    expect(replies[0]?.startsWith("HTTP/1.1 200 OK\r\n")).toBe(true);
    expect(replies[1]?.startsWith("HTTP/1.1 401 Unauthorized\r\n")).toBe(true);
    expect(replies[1]?.toLowerCase()).toContain("connection: close\r\n");
    expect(replies[1]).toContain(`"error":"${ErrorCode.TOKEN_REVOKED}"`);
    expect(upstream.seen.map((seen) => seen.url)).toEqual(["/one"]);
    expect(double.resolveForProxy).toHaveBeenCalledTimes(1);
  });

  it("undici's ProxyAgent opens a tunnel per request: each CONNECT and each request verified", async () => {
    const agent = agentWith();
    await viaTunnel(agent, "/one", { authorization: "Bearer harpoc:gh-pat" });
    await viaTunnel(agent, "/two", { authorization: "Bearer harpoc:gh-pat" });

    expect(upstream.seen.map((seen) => seen.url)).toEqual(["/one", "/two"]);
    expect(double.verifyToken).toHaveBeenCalledTimes(4);
  });

  it("a cross-origin 3xx inside the tunnel keeps its Location as sent (the client CONNECTs again), the value redacted", async () => {
    upstream.script((_req, res) => {
      res.writeHead(302, { location: `https://192.0.2.1/next?k=${SECRET_VALUE}` });
      res.end();
    });
    const reply = await viaTunnel(agentWith(), "/redir", { authorization: "Bearer harpoc:gh-pat" });

    expect(reply.status).toBe(302);
    expect(reply.headers.location).toBe(`https://192.0.2.1/next?k=${MARKER}`);
  });

  it("an absolute-form request for another authority inside the tunnel is 400 with nothing upstream", async () => {
    const answer = await exchangeInTunnel(
      await tunnelToUpstream(),
      "GET https://localhost:1/x HTTP/1.1\r\nHost: localhost:1\r\nAuthorization: Bearer harpoc:gh-pat\r\nConnection: close\r\n\r\n",
    );

    expect(answer.startsWith("HTTP/1.1 400 ")).toBe(true);
    expect(upstream.seen).toHaveLength(0);
    expect(double.resolveForProxy).not.toHaveBeenCalled();
  });

  it("keeps serving CONNECT after the caller zero-fills the key Buffer it passed (RX-B8-17)", async () => {
    await proxy.close();
    const keyPem = Buffer.from(CA.keyPem, "utf8");
    proxy = createEgressProxy({
      engine: double.engine,
      ca: { ...CA_OPTIONS, keyPem },
      onError: (err) => errors.push(err),
    });
    keyPem.fill(0);
    port = (await proxy.listenTcp(0, "127.0.0.1")).port;

    const reply = await viaTunnel(agentWith(), "/user", { authorization: "Bearer harpoc:gh-pat" });

    expect(reply.status).toBe(200);
    expect(upstream.seen[0]?.headers.authorization).toBe(`Bearer ${SECRET_VALUE}`);
    expect(reply.headers["x-echo"]).toBe(`Bearer ${MARKER}`);
  });

  describe.skipIf(!CAN_SET_DEFAULT_CA)(
    "pass-through inside the tunnel (the fixture CA trusted by default)",
    () => {
      let restore: () => void;

      beforeAll(() => {
        restore = trustFixtureCaByDefault();
      });

      afterAll(() => {
        restore();
      });

      it("no placeholder: no engine call; a Proxy-Authorization sent inside the tunnel never goes upstream", async () => {
        const answer = await exchangeInTunnel(
          await tunnelToUpstream(),
          `GET /plain HTTP/1.1\r\nHost: 127.0.0.1:${upstream.port}\r\nProxy-Authorization: Bearer ${TOKENS.use}\r\nX-Kept: 1\r\nConnection: close\r\n\r\n`,
        );

        expect(answer.startsWith("HTTP/1.1 200 ")).toBe(true);
        expect(upstream.seen[0]?.headers["proxy-authorization"]).toBeUndefined();
        expect(upstream.seen[0]?.headers["x-kept"]).toBe("1");
        expect(double.resolveForProxy).not.toHaveBeenCalled();
      });
    },
  );
});

describe("CONNECT — refusals before the 200, each closing the connection, none reaching the engine's resolve", () => {
  it("a missing Proxy-Authorization is 407 with the Basic and the Bearer challenge; nothing is verified", async () => {
    const answer = await openTunnel({
      port,
      authority: `127.0.0.1:${upstream.port}`,
      fields: [],
      ca: CA.rootPem,
    });

    const lines = answer.established.split("\r\n");
    expect(lines[0]).toBe("HTTP/1.1 407 Proxy Authentication Required");
    expect(lines.filter((line) => line.startsWith("proxy-authenticate: "))).toEqual([
      'proxy-authenticate: Basic realm="harpoc"',
      'proxy-authenticate: Bearer realm="harpoc"',
    ]);
    expect(lines).toContain("connection: close");
    expect(JSON.parse(answer.body ?? "")).toEqual({
      error: ErrorCode.INVALID_TOKEN,
      message: "Missing Proxy-Authorization header",
    });
    expect(double.verifyToken).not.toHaveBeenCalled();
  });

  it.each([
    ["undecodable Basic", "Basic !!!!"],
    ["Basic without a colon", `Basic ${Buffer.from(TOKENS.use).toString("base64")}`],
    ["Basic with an empty token", `Basic ${Buffer.from("harpoc:").toString("base64")}`],
    ["another scheme", `Negotiate ${TOKENS.use}`],
  ])("a malformed credential (%s) is 401 INVALID_TOKEN; nothing is verified", async (_t, value) => {
    const answer = await openTunnel({
      port,
      authority: `127.0.0.1:${upstream.port}`,
      fields: [`Proxy-Authorization: ${value}`],
      ca: CA.rootPem,
    });

    expect(answer.established.startsWith("HTTP/1.1 401 Unauthorized\r\n")).toBe(true);
    expect(JSON.parse(answer.body ?? "")).toMatchObject({ error: ErrorCode.INVALID_TOKEN });
    expect(double.verifyToken).not.toHaveBeenCalled();
  });

  it.each([
    ["an expired token", TOKENS.expired, 401, ErrorCode.TOKEN_EXPIRED],
    ["a revoked token", TOKENS.revoked, 401, ErrorCode.TOKEN_REVOKED],
    ["a sealed vault", TOKENS.sealed, 503, ErrorCode.VAULT_LOCKED],
  ])("%s is refused %i with the engine's code", async (_t, token, status, code) => {
    const answer = await openTunnel({
      port,
      authority: `127.0.0.1:${upstream.port}`,
      fields: [`Proxy-Authorization: Basic ${Buffer.from(`harpoc:${token}`).toString("base64")}`],
      ca: CA.rootPem,
    });

    expect(answer.established.startsWith(`HTTP/1.1 ${status} `)).toBe(true);
    expect(JSON.parse(answer.body ?? "")).toMatchObject({ error: code });
    expect(answer.established + (answer.body ?? "")).not.toContain(token);
  });

  it("a host outside the CA's hosts is 403 PROXY_CONNECT_DENIED naming host and port; no leaf, no engine call", async () => {
    const answer = await openTunnel({
      port,
      authority: "evil.example:443",
      fields: fields(),
      ca: CA.rootPem,
    });

    expect(answer.established.startsWith("HTTP/1.1 403 Forbidden\r\n")).toBe(true);
    const body = JSON.parse(answer.body ?? "") as { error: string; message: string };
    expect(body.error).toBe(ErrorCode.PROXY_CONNECT_DENIED);
    expect(body.message).toContain("evil.example:443");
    expect(errors.map((err) => err.code)).toEqual([ErrorCode.PROXY_CONNECT_DENIED]);
    expect(double.resolveForProxy).not.toHaveBeenCalled();
  });

  it.each(["127.0.0.1", "127.0.0.1:0", "127.0.0.1:443/x"])(
    "not a CONNECT target (%s) is 400 INVALID_INPUT",
    async (authority) => {
      const answer = await openTunnel({ port, authority, fields: fields(), ca: CA.rootPem });

      expect(answer.established.startsWith("HTTP/1.1 400 Bad Request\r\n")).toBe(true);
      expect(JSON.parse(answer.body ?? "")).toEqual({
        error: ErrorCode.INVALID_INPUT,
        message: "Not a CONNECT target: send CONNECT <host>:<port>",
      });
    },
  );

  it("under the unconstrained fallback CA the stored hosts still bound CONNECT (RD-B8-13): an in-set leaf verifies under the fallback root, an out-of-set CONNECT is 403", async () => {
    await proxy.close();
    const fallback = createCa({ permittedHosts: [], unconstrained: true, validityDays: 7 });
    const stored = {
      certPem: fallback.certPem,
      keyPem: fallback.keyPem,
      hosts: ["localhost"],
      unconstrained: true,
    };
    await startProxy({ ca: stored });
    const tunnel = await openTunnel({
      port,
      authority: "localhost:443",
      fields: fields(),
      ca: fallback.rootPem,
    });
    expect(tunnel.established).toBe("HTTP/1.1 200 Connection Established");
    expect(tunnel.socket?.authorized).toBe(true);
    tunnel.socket?.destroy();

    const refused = await openTunnel({
      port,
      authority: "evil.example:443",
      fields: fields(),
      ca: fallback.rootPem,
    });
    expect(refused.established.startsWith("HTTP/1.1 403 Forbidden\r\n")).toBe(true);
    expect(JSON.parse(refused.body ?? "")).toMatchObject({ error: ErrorCode.PROXY_CONNECT_DENIED });
  });

  it("a CA past its notAfter answers the authenticated CONNECT 410 CERT_EXPIRED with connection: close; no tunnel", async () => {
    await proxy.close();
    const shortLived = createCa({ permittedHosts: HOSTS, validityDays: 1 });
    await startProxy({
      ca: { certPem: shortLived.certPem, keyPem: shortLived.keyPem, hosts: HOSTS },
    });
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 2 * 86_400_000);

    const answer = await openTunnel({
      port,
      authority: `127.0.0.1:${upstream.port}`,
      fields: fields(),
      ca: shortLived.rootPem,
    });

    const lines = answer.established.split("\r\n");
    expect(lines[0]).toBe("HTTP/1.1 410 Gone");
    expect(lines).toContain("connection: close");
    expect(answer.socket).toBeUndefined();
    expect(JSON.parse(answer.body ?? "")).toMatchObject({ error: ErrorCode.CERT_EXPIRED });
    expect(errors.map((err) => err.code)).toEqual([ErrorCode.CERT_EXPIRED]);
    expect(double.resolveForProxy).not.toHaveBeenCalled();
  });
});

describe("CONNECT — the TLS side and the lifecycle", () => {
  it("ALPN is http/1.1 alone: a client offering only h2 fails the handshake, the proxy keeps serving", async () => {
    await expect(
      openTunnel({
        port,
        authority: `127.0.0.1:${upstream.port}`,
        fields: fields(),
        ca: CA.rootPem,
        alpn: ["h2"],
      }),
    ).rejects.toMatchObject({ code: "ERR_SSL_TLSV1_ALERT_NO_APPLICATION_PROTOCOL" });
    const reply = await viaTunnel(agentWith(), "/after", { authorization: "Bearer harpoc:gh-pat" });
    expect(reply.status).toBe(200);
  });

  it("a client that resets the connection after the 200 leaves the proxy serving", async () => {
    await new Promise<void>((resolve, reject) => {
      const raw = connect(port, "127.0.0.1");
      raw.setTimeout(PROXY_CLIENT_TIMEOUT_MS, () => raw.destroy(new Error("timed out")));
      raw.once("error", reject);
      raw.once("data", () => {
        raw.resetAndDestroy();
        resolve();
      });
      raw.write(
        `CONNECT 127.0.0.1:${upstream.port} HTTP/1.1\r\nHost: 127.0.0.1:${upstream.port}\r\n${fields()[0] as string}\r\n\r\n`,
      );
    });
    const reply = await viaTunnel(agentWith(), "/after", { authorization: "Bearer harpoc:gh-pat" });
    expect(reply.status).toBe(200);
  });

  it("a raw storage error during a CONNECT's token check is answered 500 and the daemon keeps serving (E-16)", async () => {
    double.verifyToken.mockImplementationOnce(() => {
      throw new Error("injected storage failure");
    });

    const failed = await openTunnel({
      port,
      authority: `127.0.0.1:${upstream.port}`,
      fields: fields(),
      ca: CA.rootPem,
    });

    const lines = failed.established.split("\r\n");
    expect(lines[0]).toBe("HTTP/1.1 500 Internal Server Error");
    expect(lines).toContain("connection: close");
    expect(failed.socket).toBeUndefined();
    expect(JSON.parse(failed.body ?? "")).toEqual({
      error: ErrorCode.INTERNAL_ERROR,
      message: "Internal proxy error",
    });
    expect(errors.map((err) => err.code)).toEqual([ErrorCode.INTERNAL_ERROR]);

    const served = await openTunnel({
      port,
      authority: `127.0.0.1:${upstream.port}`,
      fields: fields(),
      ca: CA.rootPem,
    });
    expect(served.established).toBe("HTTP/1.1 200 Connection Established");
    served.socket?.destroy();
  });

  it("close() ends an in-flight request inside a tunnel; its lease completes before close() resolves", async () => {
    upstream.script((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.write("x".repeat(64));
    });
    const res = await request(`${upstream.origin}/stream`, {
      dispatcher: agentWith(),
      headers: { authorization: "Bearer harpoc:gh-pat" },
      headersTimeout: PROXY_CLIENT_TIMEOUT_MS,
    });
    res.body.on("error", () => undefined);

    await proxy.close();

    expect(res.statusCode).toBe(200);
    expect(double.leases[0]?.complete).toHaveBeenCalledTimes(1);
    expect(double.leases[0]?.complete).toHaveBeenCalledWith({ status: 200, sanitized: false });
  });

  it("an idle tunnel does not hold close(): it is destroyed and close() resolves", async () => {
    const tunnel = await openTunnel({
      port,
      authority: `127.0.0.1:${upstream.port}`,
      fields: fields(),
      ca: CA.rootPem,
    });
    const closed = new Promise<void>((resolve) => tunnel.socket?.once("close", () => resolve()));

    await proxy.close();
    await closed;

    expect(tunnel.socket?.destroyed).toBe(true);
  });

  it("a tunnel that stays silent after the handshake is destroyed once the proxy's timeoutMs passes", async () => {
    await proxy.close();
    await startProxy({ timeoutMs: 200 });
    const tunnel = await openTunnel({
      port,
      authority: `127.0.0.1:${upstream.port}`,
      fields: fields(),
      ca: CA.rootPem,
    });
    const socket = tunnel.socket as TLSSocket;

    const closed = await new Promise<boolean>((resolve) => {
      const bound = setTimeout(() => resolve(false), 2_000);
      socket.once("close", () => {
        clearTimeout(bound);
        resolve(true);
      });
    });
    socket.destroy();

    expect(closed).toBe(true);
    expect(upstream.seen).toHaveLength(0);
  });

  it("a tunnelled request whose upstream holds its head past timeoutMs gets the upstream budget's 502, not a cut tunnel", async () => {
    await proxy.close();
    await startProxy({ timeoutMs: 200 });
    upstream.script((_req, res) => {
      const held = setTimeout(() => res.end(), 2_000);
      res.once("close", () => clearTimeout(held));
    });

    const answer = await exchangeInTunnel(await tunnelToUpstream(), line("/slow", true));

    expect(answer.startsWith("HTTP/1.1 502 ")).toBe(true);
    expect(answer).toContain(`"error":"${ErrorCode.PROXY_UPSTREAM_FAILED}"`);
    expect(upstream.seen).toHaveLength(1);
  });
});
