import { request } from "node:http";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode, RateLimiter, VaultError } from "@harpoc/shared";
import type { EgressProxy, EgressProxyOptions } from "./proxy.js";
import { createEgressProxy } from "./proxy.js";
import {
  SECRET_VALUE,
  TOKENS,
  engineDouble,
  recordingLease,
} from "./__fixtures__/engine-double.js";
import type { EngineDouble, RecordingLease } from "./__fixtures__/engine-double.js";
import {
  PROXY_CLIENT_TIMEOUT_MS,
  proxyRequest,
  rawProxyExchange,
} from "./__fixtures__/proxy-client.js";
import type { ProxyReply } from "./__fixtures__/proxy-client.js";
import {
  CAN_SET_DEFAULT_CA,
  deadPort,
  startUpstream,
  trustFixtureCaByDefault,
} from "./__fixtures__/upstream-server.js";
import type { UpstreamFixture } from "./__fixtures__/upstream-server.js";

const MARKER = "[REDACTED]";

let upstream: UpstreamFixture;
let double: EngineDouble;
let proxy: EgressProxy;
let port: number;
let errors: VaultError[];

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
    onError: (err) => errors.push(err),
    ...extra,
  });
  port = (await proxy.listenTcp(0, "127.0.0.1")).port;
}

beforeEach(async () => {
  upstream.seen.length = 0;
  upstream.script((_req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
  });
  await startProxy();
});

afterEach(async () => {
  await proxy.close();
});

/** A request to the upstream fixture through the path-prefixed form, authenticated as `tok-use`. */
function send(
  path: string,
  headers: Record<string, string> = {},
  extra: { method?: string; body?: string; token?: string | null } = {},
): Promise<ProxyReply> {
  const token = extra.token === undefined ? TOKENS.use : extra.token;
  return proxyRequest({
    port,
    path: `/127.0.0.1:${upstream.port}${path}`,
    headers: {
      ...(token === null ? {} : { "proxy-authorization": `Bearer ${token}` }),
      ...headers,
    },
    ...(extra.method === undefined ? {} : { method: extra.method }),
    ...(extra.body === undefined ? {} : { body: extra.body }),
  });
}

/** The upstream echoes every request field it was sent, and the `Authorization` value as a response field. */
function echoHeaders(): void {
  upstream.script((req, res) => {
    res.writeHead(200, {
      "content-type": "application/json",
      "x-echo": req.headers.authorization ?? "",
    });
    res.end(JSON.stringify(req.headers));
  });
}

const BASIC = (userPass: string): string => `Basic ${Buffer.from(userPass).toString("base64")}`;

describe("brokered requests — the four placements", () => {
  it("a bearer placeholder is swapped upstream and redacted in the reply; one lease, completed {200, sanitized}", async () => {
    echoHeaders();
    const reply = await send("/user", {
      authorization: "Bearer harpoc:gh-pat",
      "accept-encoding": "gzip",
    });

    const seen = upstream.seen[0];
    expect(upstream.seen).toHaveLength(1);
    expect(seen?.headers.authorization).toBe(`Bearer ${SECRET_VALUE}`);
    expect(seen?.headers["proxy-authorization"]).toBeUndefined();
    expect(seen?.headers["accept-encoding"]).toBe("identity");
    expect(seen?.headers.host).toBe(`127.0.0.1:${upstream.port}`);

    expect(reply.status).toBe(200);
    expect(reply.headers["x-echo"]).toBe(`Bearer ${MARKER}`);
    expect(JSON.parse(reply.body)).toMatchObject({ authorization: `Bearer ${MARKER}` });
    expect(reply.headers["content-length"]).toBeUndefined();
    expect(reply.headers["transfer-encoding"]).toBe("chunked");
    expect(reply.raw).not.toContain(SECRET_VALUE);

    expect(double.resolveForProxy).toHaveBeenCalledTimes(1);
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
    const lease = double.leases[0];
    expect(lease?.complete).toHaveBeenCalledTimes(1);
    expect(lease?.complete).toHaveBeenCalledWith({ status: 200, sanitized: true });
    expect([...(lease?.value ?? [1])].every((byte) => byte === 0)).toBe(true);
  });

  it("a basic-auth placeholder keeps the request's user; the base64 form is redacted too", async () => {
    echoHeaders();
    const reply = await send("/user", { authorization: BASIC("alice:harpoc:gh-pat") });

    const sent = BASIC(`alice:${SECRET_VALUE}`);
    expect(upstream.seen[0]?.headers.authorization).toBe(sent);
    expect(reply.raw).not.toContain(sent.slice("Basic ".length));
    expect(reply.raw).not.toContain(SECRET_VALUE);
    expect(reply.headers["x-echo"]).toBe(`Basic ${MARKER}`);
    expect(double.leases[0]?.complete).toHaveBeenCalledWith({ status: 200, sanitized: true });
  });

  it("a whole-value header placeholder is swapped by name and resolves its project handle", async () => {
    const reply = await send("/data", { "x-api-key": "harpoc://team/api-key" });

    expect(reply.status).toBe(200);
    expect(upstream.seen[0]?.headers["x-api-key"]).toBe(SECRET_VALUE);
    expect(double.resolveForProxy.mock.calls[0]?.[0]).toBe("secret://team/api-key");
    expect(double.leases[0]?.complete).toHaveBeenCalledWith({ status: 200, sanitized: false });
  });

  it("a query placeholder is swapped in place; the judged path carries no query", async () => {
    const reply = await send("/q?token=harpoc:gh-pat&x=1");

    expect(reply.status).toBe(200);
    expect(upstream.seen[0]?.url).toBe(`/q?token=${SECRET_VALUE}&x=1`);
    expect(double.resolveForProxy.mock.calls[0]?.[2]).toEqual({
      method: "GET",
      origin: upstream.origin,
      path: "/q",
    });
  });

  it("an absolute http:// target is judged and sent as https — the rewrite mode's rule, not the engine's", async () => {
    const reply = await proxyRequest({
      port,
      path: `http://127.0.0.1:${upstream.port}/abs`,
      headers: {
        "proxy-authorization": `Bearer ${TOKENS.use}`,
        authorization: "Bearer harpoc:gh-pat",
      },
    });

    expect(reply.status).toBe(200);
    expect(double.resolveForProxy.mock.calls[0]?.[2]).toEqual({
      method: "GET",
      origin: `https://127.0.0.1:${upstream.port}`,
      path: "/abs",
    });
    expect(upstream.seen[0]?.headers.authorization).toBe(`Bearer ${SECRET_VALUE}`);
  });

  it("a brokered request body streams upstream unchanged", async () => {
    const reply = await send(
      "/post",
      { authorization: "Bearer harpoc:gh-pat", "content-type": "text/plain" },
      { method: "POST", body: "payload-123" },
    );

    expect(reply.status).toBe(200);
    expect(upstream.seen[0]).toMatchObject({ method: "POST", body: "payload-123" });
    expect(upstream.seen[0]?.headers["content-length"]).toBe("11");
  });
});

// No lease, no CA pin: these rows trust the fixture CA through the default store,
// which tls.setDefaultCACertificates needs (Node >= 22.19 / 24.5).
describe.skipIf(!CAN_SET_DEFAULT_CA)("pass-through — no placeholder", () => {
  let restore: () => void;

  beforeAll(() => {
    restore = trustFixtureCaByDefault();
  });

  afterAll(() => {
    restore();
  });

  it("is forwarded with the client's own fields: no engine call, no lease, Content-Length kept", async () => {
    upstream.script((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain", "content-length": "2" });
      res.end("ok");
    });
    const reply = await send("/plain", { "accept-encoding": "gzip", "x-custom": "1" });

    expect(reply.status).toBe(200);
    expect(reply.body).toBe("ok");
    expect(reply.headers["content-length"]).toBe("2");
    expect(upstream.seen[0]?.headers["accept-encoding"]).toBe("gzip");
    expect(upstream.seen[0]?.headers["x-custom"]).toBe("1");
    expect(upstream.seen[0]?.headers["proxy-authorization"]).toBeUndefined();
    expect(double.resolveForProxy).not.toHaveBeenCalled();
  });

  it.each([
    ["an http:// absolute URI, upgraded to TLS upstream", "http"],
    ["an https:// absolute URI", "https"],
  ])("the absolute-URI form: %s", async (_title, scheme) => {
    const reply = await proxyRequest({
      port,
      path: `${scheme}://127.0.0.1:${upstream.port}/abs?x=1`,
      headers: { "proxy-authorization": `Bearer ${TOKENS.use}` },
    });

    expect(reply.status).toBe(200);
    expect(upstream.seen[0]?.url).toBe("/abs?x=1");
  });

  it("hop-by-hop fields and every Connection option stay on the client's hop", async () => {
    const reply = await send("/hop", {
      connection: "keep-alive, x-hop",
      "x-hop": "1",
      "keep-alive": "timeout=5",
      te: "trailers",
      "proxy-connection": "Keep-Alive",
      "x-kept": "1",
    });

    expect(reply.status).toBe(200);
    const seen = upstream.seen[0]?.headers ?? {};
    for (const name of ["x-hop", "keep-alive", "te", "proxy-connection"]) {
      expect(seen[name]).toBeUndefined();
    }
    expect(seen["x-kept"]).toBe("1");
  });

  it.each([
    ["no host segment", "/"],
    ["userinfo in the host segment", "/a@b.example/x"],
    ["a scheme other than http(s)", "ftp://127.0.0.1/x"],
    ["credentials in an absolute URI", "http://u:p@127.0.0.1/x"],
  ])("a malformed target (%s) is 400 INVALID_INPUT with nothing upstream", async (_title, path) => {
    const reply = await proxyRequest({
      port,
      path,
      headers: { "proxy-authorization": `Bearer ${TOKENS.use}` },
    });

    expect(reply.status).toBe(400);
    expect(JSON.parse(reply.body)).toEqual({
      error: ErrorCode.INVALID_INPUT,
      message:
        "Not a proxy request target: send http://<proxy>/<host>[:<port>]/<path> or an absolute http:// or https:// URI",
    });
    expect(upstream.seen).toHaveLength(0);
  });
});

describe("caller authentication — Proxy-Authorization on every request", () => {
  it("a missing header is 407 with the Bearer challenge; nothing is verified or sent upstream", async () => {
    const reply = await send("/user", { authorization: "Bearer harpoc:gh-pat" }, { token: null });

    expect(reply.status).toBe(407);
    expect(reply.headers["proxy-authenticate"]).toBe('Bearer realm="harpoc"');
    expect(JSON.parse(reply.body)).toEqual({
      error: ErrorCode.INVALID_TOKEN,
      message: "Missing Proxy-Authorization header",
    });
    expect(double.verifyToken).not.toHaveBeenCalled();
    expect(upstream.seen).toHaveLength(0);
  });

  it.each([
    ["not a Bearer credential", "Basic dXNlcjpwdw==", 401, ErrorCode.INVALID_TOKEN],
    ["an invalid token", "Bearer tok-bogus", 401, ErrorCode.INVALID_TOKEN],
    ["an expired token", `Bearer ${TOKENS.expired}`, 401, ErrorCode.TOKEN_EXPIRED],
    ["a revoked token", `Bearer ${TOKENS.revoked}`, 401, ErrorCode.TOKEN_REVOKED],
    ["a sealed vault", `Bearer ${TOKENS.sealed}`, 503, ErrorCode.VAULT_LOCKED],
  ])(
    "%s is refused %i with its code; no lease, nothing upstream",
    async (_t, header, status, code) => {
      const reply = await proxyRequest({
        port,
        path: `/127.0.0.1:${upstream.port}/user`,
        headers: { "proxy-authorization": header, authorization: "Bearer harpoc:gh-pat" },
      });

      expect(reply.status).toBe(status);
      expect(JSON.parse(reply.body)).toMatchObject({ error: code });
      expect(reply.raw).not.toContain(header.slice("Bearer ".length));
      expect(double.resolveForProxy).not.toHaveBeenCalled();
      expect(upstream.seen).toHaveLength(0);
    },
  );
});

describe("refusals before the lease", () => {
  it("two placeholders are 403 PROXY_PLACEHOLDER_DENIED before any resolution", async () => {
    const reply = await send("/q?token=harpoc:other", { authorization: "Bearer harpoc:gh-pat" });

    expect(reply.status).toBe(403);
    expect(JSON.parse(reply.body)).toEqual({
      error: ErrorCode.PROXY_PLACEHOLDER_DENIED,
      message: `Placeholder refused for ${upstream.origin}: one placeholder per request`,
    });
    expect(double.resolveForProxy).not.toHaveBeenCalled();
    expect(upstream.seen).toHaveLength(0);
  });

  it.each([
    ["a token without use scope", TOKENS.read, "permission"],
    ["a project-claimed token on a project-less placeholder", TOKENS.project, "project"],
  ])(
    "%s is 403 ACCESS_DENIED after its access.denied row, before any resolution",
    async (_t, token, reason) => {
      const reply = await send("/user", { authorization: "Bearer harpoc:gh-pat" }, { token });

      expect(reply.status).toBe(403);
      expect(JSON.parse(reply.body)).toMatchObject({ error: ErrorCode.ACCESS_DENIED });
      expect(double.auditScopeRefusal).toHaveBeenCalledTimes(1);
      expect(double.auditScopeRefusal).toHaveBeenCalledWith(
        expect.objectContaining({ principal_id: "agent-a", interface: "proxy" }),
        `GET ${upstream.origin}/user`,
        reason,
      );
      expect(double.resolveForProxy).not.toHaveBeenCalled();
      expect(upstream.seen).toHaveLength(0);
    },
  );

  it.each([
    [ErrorCode.PROXY_PLACEHOLDER_DENIED, "Secret not enabled for the egress proxy", 403],
    [ErrorCode.URL_NOT_ALLOWED, "URL not in secret allowlist: https://127.0.0.1", 403],
    [ErrorCode.ACCESS_DENIED, "Access denied", 403],
    [ErrorCode.SECRET_NOT_FOUND, "Secret not found: secret://gh-pat", 404],
    [ErrorCode.VAULT_LOCKED, "Vault is locked", 503],
  ])(
    "the engine's %s is answered with its status, code and message verbatim; nothing upstream",
    async (code, message, status) => {
      double.resolveForProxy.mockRejectedValueOnce(new VaultError(code, message));
      const reply = await send("/user", { authorization: "Bearer harpoc:gh-pat" });

      expect(reply.status).toBe(status);
      expect(JSON.parse(reply.body)).toEqual({ error: code, message });
      expect(upstream.seen).toHaveLength(0);
    },
  );

  it("the per-handle rate limit answers 429 before the engine is asked", async () => {
    await proxy.close();
    await startProxy({ rateLimiter: new RateLimiter(1000, 60, 2) });
    const brokered = (handle: string) =>
      send("/user", { authorization: `Bearer harpoc:${handle}` });

    expect((await brokered("gh-pat")).status).toBe(200);
    expect((await brokered("gh-pat")).status).toBe(200);
    const limited = await brokered("gh-pat");
    expect(limited.status).toBe(429);
    expect(JSON.parse(limited.body)).toEqual({
      error: ErrorCode.RATE_LIMIT_EXCEEDED,
      message: "Per-secret rate limit exceeded",
    });
    expect(double.resolveForProxy).toHaveBeenCalledTimes(2);
    expect((await brokered("other")).status).toBe(200);
  });
});

describe("the upstream leg", () => {
  it("an unreachable upstream is 502 PROXY_UPSTREAM_FAILED naming the origin; the lease completes with the error", async () => {
    const dead = await deadPort();
    const reply = await proxyRequest({
      port,
      path: `/127.0.0.1:${dead}/x`,
      headers: {
        "proxy-authorization": `Bearer ${TOKENS.use}`,
        authorization: "Bearer harpoc:gh-pat",
      },
    });

    expect(reply.status).toBe(502);
    expect(JSON.parse(reply.body)).toEqual({
      error: ErrorCode.PROXY_UPSTREAM_FAILED,
      message: expect.stringContaining(`https://127.0.0.1:${dead}`),
    });
    const { message } = JSON.parse(reply.body) as { message: string };
    expect(message).toBe(
      `Egress proxy upstream request failed (refused): https://127.0.0.1:${dead}`,
    );
    expect(message).not.toMatch(/ECONNREFUSED|UND_ERR_|self-signed|DEPTH_ZERO/);
    expect(reply.raw).not.toMatch(/ECONNREFUSED/);
    expect(double.leases[0]?.complete).toHaveBeenCalledTimes(1);
    expect(double.leases[0]?.complete).toHaveBeenCalledWith({
      error: ErrorCode.PROXY_UPSTREAM_FAILED,
    });
  });

  it("a lease without the CA pin fails the handshake against the self-signed upstream: 502", async () => {
    double.resolveForProxy.mockResolvedValueOnce(recordingLease(SECRET_VALUE, null));
    const reply = await send("/user", { authorization: "Bearer harpoc:gh-pat" });

    expect(reply.status).toBe(502);
    expect(JSON.parse(reply.body)).toEqual({
      error: ErrorCode.PROXY_UPSTREAM_FAILED,
      message: expect.stringContaining(upstream.origin),
    });
    const { message } = JSON.parse(reply.body) as { message: string };
    expect(message).toBe(`Egress proxy upstream request failed (tls): ${upstream.origin}`);
    expect(message).not.toMatch(/ECONNREFUSED|UND_ERR_|self-signed|DEPTH_ZERO/);
    expect(reply.raw).not.toMatch(/self-signed|DEPTH_ZERO/);
    expect(upstream.seen).toHaveLength(0);
  });

  it("the SSRF floor refuses a private literal on a pass-through: 403, no engine call", async () => {
    const reply = await proxyRequest({
      port,
      path: "/10.0.0.1/x",
      headers: { "proxy-authorization": `Bearer ${TOKENS.use}` },
    });

    expect(reply.status).toBe(403);
    expect(JSON.parse(reply.body)).toMatchObject({ error: ErrorCode.SSRF_BLOCKED });
    expect(double.resolveForProxy).not.toHaveBeenCalled();
  });

  it("the SSRF floor refuses a private literal on a brokered request: 403, the lease completes SSRF_BLOCKED", async () => {
    const reply = await proxyRequest({
      port,
      path: "/10.0.0.1/x",
      headers: {
        "proxy-authorization": `Bearer ${TOKENS.use}`,
        authorization: "Bearer harpoc:gh-pat",
      },
    });

    expect(reply.status).toBe(403);
    expect(JSON.parse(reply.body)).toMatchObject({ error: ErrorCode.SSRF_BLOCKED });
    expect(double.leases[0]?.complete).toHaveBeenCalledTimes(1);
    expect(double.leases[0]?.complete).toHaveBeenCalledWith({ error: ErrorCode.SSRF_BLOCKED });
  });

  it("an upstream that sends no head within the budget is 502", async () => {
    await proxy.close();
    await startProxy({ timeoutMs: 300 });
    upstream.script(() => {
      // never answers
    });
    const reply = await send("/hang", { authorization: "Bearer harpoc:gh-pat" });

    expect(reply.status).toBe(502);
    expect(JSON.parse(reply.body)).toMatchObject({ error: ErrorCode.PROXY_UPSTREAM_FAILED });
    const { message } = JSON.parse(reply.body) as { message: string };
    expect(message).toBe(`Egress proxy upstream request failed (timeout): ${upstream.origin}`);
    expect(message).not.toMatch(/ECONNREFUSED|UND_ERR_|self-signed|DEPTH_ZERO/);
    expect(double.leases[0]?.complete).toHaveBeenCalledWith({
      error: ErrorCode.PROXY_UPSTREAM_FAILED,
    });
  });

  it("a cross-origin 3xx on a base-URL request is relayed, not followed: Location rewritten to /<host>/<path>, the value redacted", async () => {
    upstream.script((_req, res) => {
      res.writeHead(302, { location: `https://objects.example:8443/cb?code=${SECRET_VALUE}` });
      res.end();
    });
    const reply = await send("/login", { authorization: "Bearer harpoc:gh-pat" });

    expect(reply.status).toBe(302);
    expect(reply.headers.location).toBe(`/objects.example:8443/cb?code=${MARKER}`);
    expect(upstream.seen).toHaveLength(1);
    expect(double.leases[0]?.complete).toHaveBeenCalledWith({ status: 302, sanitized: true });
  });

  it("a cross-origin 3xx on an absolute-form request keeps its Location as sent, the value redacted", async () => {
    upstream.script((_req, res) => {
      res.writeHead(302, { location: `https://objects.example/cb?code=${SECRET_VALUE}` });
      res.end();
    });
    const reply = await proxyRequest({
      port,
      path: `http://127.0.0.1:${upstream.port}/login`,
      headers: {
        "proxy-authorization": `Bearer ${TOKENS.use}`,
        authorization: "Bearer harpoc:gh-pat",
      },
    });

    expect(reply.status).toBe(302);
    expect(reply.headers.location).toBe(`https://objects.example/cb?code=${MARKER}`);
    expect(upstream.seen).toHaveLength(1);
  });

  it("a fragment-only Location on a query placement maps to the client's own target: the placeholder, never the value", async () => {
    upstream.script((_req, res) => {
      res.writeHead(302, { location: "#frag" });
      res.end();
    });
    const reply = await send("/q?token=harpoc:gh-pat&x=1");

    expect(reply.status).toBe(302);
    expect(reply.headers.location).toBe(`/127.0.0.1:${upstream.port}/q?token=harpoc:gh-pat&x=1`);
    expect(reply.raw).not.toContain(SECRET_VALUE);
    expect(upstream.seen[0]?.url).toBe(`/q?token=${SECRET_VALUE}&x=1`);
    expect(double.leases[0]?.complete).toHaveBeenCalledWith({ status: 302, sanitized: false });
  });

  it("an upstream error body is relayed with the value redacted", async () => {
    upstream.script((_req, res) => {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ message: `bad credentials ${SECRET_VALUE}` }));
    });
    const reply = await send("/user", { authorization: "Bearer harpoc:gh-pat" });

    expect(reply.status).toBe(401);
    expect(JSON.parse(reply.body)).toEqual({ message: `bad credentials ${MARKER}` });
    expect(double.leases[0]?.complete).toHaveBeenCalledWith({ status: 401, sanitized: true });
  });

  it("the response head reaches the client before the redactor releases a byte", async () => {
    upstream.script((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      // Shorter than the held-back window: no body byte is released yet.
      res.write("x");
    });
    const status = await new Promise<number>((resolve, reject) => {
      const req = request(
        {
          host: "127.0.0.1",
          port,
          path: `/127.0.0.1:${upstream.port}/slow`,
          headers: {
            "proxy-authorization": `Bearer ${TOKENS.use}`,
            authorization: "Bearer harpoc:gh-pat",
          },
          agent: false,
        },
        (res) => {
          resolve(res.statusCode ?? 0);
          req.destroy();
        },
      );
      req.setTimeout(PROXY_CLIENT_TIMEOUT_MS, () => req.destroy(new Error("no head in time")));
      req.on("error", (err) => {
        if ((err as NodeJS.ErrnoException).code !== "ECONNRESET") reject(err);
      });
      req.end();
    });

    expect(status).toBe(200);
    await vi.waitFor(() => expect(double.leases[0]?.complete).toHaveBeenCalledTimes(1));
  });

  it("a client gone mid-body completes the lease once, with the status that was sent", async () => {
    upstream.script((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      // Longer than the redactor's held-back window (the needle's length − 1).
      res.write("x".repeat(64));
    });
    await new Promise<void>((resolve, reject) => {
      const req = request(
        {
          host: "127.0.0.1",
          port,
          path: `/127.0.0.1:${upstream.port}/stream`,
          headers: {
            "proxy-authorization": `Bearer ${TOKENS.use}`,
            authorization: "Bearer harpoc:gh-pat",
          },
          agent: false,
        },
        (res) => {
          res.once("data", () => {
            req.destroy();
            resolve();
          });
        },
      );
      req.setTimeout(PROXY_CLIENT_TIMEOUT_MS, () => req.destroy(new Error("timed out")));
      req.on("error", (err) => {
        if ((err as NodeJS.ErrnoException).code !== "ECONNRESET") reject(err);
      });
      req.end();
    });

    await vi.waitFor(() => expect(double.leases[0]?.complete).toHaveBeenCalled());
    expect(double.leases[0]?.complete).toHaveBeenCalledTimes(1);
    expect(double.leases[0]?.complete).toHaveBeenCalledWith({ status: 200, sanitized: false });
  });

  it("close() ends an in-flight brokered request; its lease completes before close() resolves", async () => {
    upstream.script((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.write("x".repeat(64));
    });
    await new Promise<void>((resolve, reject) => {
      const req = request(
        {
          host: "127.0.0.1",
          port,
          path: `/127.0.0.1:${upstream.port}/stream`,
          headers: {
            "proxy-authorization": `Bearer ${TOKENS.use}`,
            authorization: "Bearer harpoc:gh-pat",
          },
          agent: false,
        },
        (res) => {
          res.on("error", () => undefined);
          res.once("data", () => resolve());
        },
      );
      req.setTimeout(PROXY_CLIENT_TIMEOUT_MS, () => req.destroy(new Error("timed out")));
      req.on("error", (err) => reject(err));
      req.end();
    });

    await proxy.close();

    expect(double.leases[0]?.complete).toHaveBeenCalledTimes(1);
    expect(double.leases[0]?.complete).toHaveBeenCalledWith({ status: 200, sanitized: false });
  });

  it("a request still resolving when close() starts never reaches upstream; its lease completes with the failure", async () => {
    let release: ((lease: RecordingLease) => void) | undefined;
    double.resolveForProxy.mockImplementationOnce(
      () =>
        new Promise<RecordingLease>((resolve) => {
          release = resolve;
        }),
    );
    const pending = send("/late", { authorization: "Bearer harpoc:gh-pat" }).catch(
      (err: unknown) => err,
    );
    await vi.waitFor(() => expect(double.resolveForProxy).toHaveBeenCalled());

    const closing = proxy.close();
    const lease = recordingLease();
    (release as (lease: RecordingLease) => void)(lease);
    await closing;
    await pending;

    expect(upstream.seen).toHaveLength(0);
    expect(lease.complete).toHaveBeenCalledTimes(1);
    expect(lease.complete).toHaveBeenCalledWith({ error: ErrorCode.PROXY_UPSTREAM_FAILED });
  });

  it("CONNECT is answered 501 without reaching the engine", async () => {
    const answer = await rawProxyExchange(
      port,
      `CONNECT 127.0.0.1:${upstream.port} HTTP/1.1\r\nHost: 127.0.0.1:${upstream.port}\r\nProxy-Authorization: Bearer ${TOKENS.use}\r\n\r\n`,
    );

    expect(answer.startsWith("HTTP/1.1 501 Not Implemented\r\n")).toBe(true);
    expect(JSON.parse(answer.slice(answer.indexOf("\r\n\r\n") + 4))).toMatchObject({
      error: ErrorCode.INVALID_INPUT,
    });
    expect(double.verifyToken).not.toHaveBeenCalled();
    expect(upstream.seen).toHaveLength(0);
  });

  it("the value reaches no client byte and no onError text on a refusal after the lease", async () => {
    const dead = await deadPort();
    const cases: [string, string][] = [
      ["10.0.0.1", "/10.0.0.1/x"],
      ["127.0.0.1", `/127.0.0.1:${dead}/x`],
    ];
    for (const [value, path] of cases) {
      double.resolveForProxy.mockResolvedValueOnce(recordingLease(value));
      const reply = await proxyRequest({
        port,
        path,
        headers: {
          "proxy-authorization": `Bearer ${TOKENS.use}`,
          authorization: "Bearer harpoc:gh-pat",
        },
      });
      expect(reply.raw).toContain(MARKER);
      expect(reply.raw).not.toContain(value);
    }
    expect(errors.map((err) => err.message).join("\n")).not.toMatch(/10\.0\.0\.1|127\.0\.0\.1/);
  });

  it("a refusal after the lease records its own code on the row and in onError; the client gets the generic 500", async () => {
    const lease = recordingLease(`${SECRET_VALUE}\r\nx-injected: 1`);
    double.resolveForProxy.mockResolvedValueOnce(lease);
    const reply = await send("/user", { authorization: "Bearer harpoc:gh-pat" });

    expect(reply.status).toBe(500);
    expect(JSON.parse(reply.body)).toEqual({
      error: ErrorCode.INTERNAL_ERROR,
      message: "Internal proxy error",
    });
    expect(reply.raw).not.toContain(SECRET_VALUE);
    expect(upstream.seen).toHaveLength(0);
    expect(lease.complete).toHaveBeenCalledTimes(1);
    expect(lease.complete).toHaveBeenCalledWith({ error: ErrorCode.INVALID_INJECTION_CONFIG });
    expect(errors).toHaveLength(1);
    expect(errors[0]?.code).toBe(ErrorCode.INVALID_INJECTION_CONFIG);
    expect(errors[0]?.message).not.toContain(SECRET_VALUE);
    expect([...lease.value].every((byte) => byte === 0)).toBe(true);
  });

  it("an onError hook that throws changes no answer, and close() still settles", async () => {
    await proxy.close();
    await startProxy({
      onError: () => {
        throw new Error("hook failed");
      },
    });
    const reply = await send("/user", {}, { token: null });

    expect(reply.status).toBe(407);
    await expect(proxy.close()).resolves.toBeUndefined();
  });
});
