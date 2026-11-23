import type { TLSSocket } from "node:tls";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createCa } from "@harpoc/cert-manager";
import type { ProxyTarget } from "@harpoc/core";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { ProxyCaOptions } from "./ca.js";
import type { EgressProxy } from "./proxy.js";
import { createEgressProxy } from "./proxy.js";
import {
  SECRET_VALUE,
  TOKENS,
  engineDouble,
  recordingLease,
} from "./__fixtures__/engine-double.js";
import type { EngineDouble } from "./__fixtures__/engine-double.js";
import { startPlainUpstream } from "./__fixtures__/plain-upstream.js";
import type { PlainUpstreamFixture } from "./__fixtures__/plain-upstream.js";
import { proxyRequest } from "./__fixtures__/proxy-client.js";
import type { ProxyReply } from "./__fixtures__/proxy-client.js";
import { exchangeInTunnel, openTunnel } from "./__fixtures__/tunnel-client.js";
import { deadPort } from "./__fixtures__/upstream-server.js";
import { expectAbsent, isIpv6BindUnavailable } from "@harpoc/test-utils";

const MARKER = "[REDACTED]";
const PLACEHOLDER = { authorization: "Bearer harpoc:gh-pat" };
const HOSTS = ["127.0.0.1", "localhost"];
const CA = createCa({ permittedHosts: HOSTS, validityDays: 30 });
const CA_OPTIONS: ProxyCaOptions = { certPem: CA.certPem, keyPem: CA.keyPem, hosts: HOSTS };

let upstream: PlainUpstreamFixture;
let double: EngineDouble;
let proxy: EgressProxy;
let port: number;
let errors: VaultError[];

beforeAll(async () => {
  upstream = await startPlainUpstream();
});

afterAll(async () => {
  await upstream.close();
});

beforeEach(async () => {
  upstream.seen.length = 0;
  upstream.script((req, res) => {
    res.writeHead(200, {
      "content-type": "application/json",
      "x-echo": req.headers.authorization ?? "",
    });
    res.end(JSON.stringify(req.headers));
  });
  double = engineDouble();
  double.resolveForProxy.mockImplementation(async (_handle, _caller, target) => {
    const lease =
      target.plainOrigin === undefined
        ? recordingLease()
        : recordingLease(SECRET_VALUE, null, true);
    double.leases.push(lease);
    return lease;
  });
  errors = [];
  proxy = createEgressProxy({
    engine: double.engine,
    ca: CA_OPTIONS,
    onError: (err) => errors.push(err),
  });
  port = (await proxy.listenTcp(0, "127.0.0.1")).port;
});

afterEach(async () => {
  await proxy.close();
});

function send(target: string, headers: Record<string, string> = PLACEHOLDER): Promise<ProxyReply> {
  return proxyRequest({
    port,
    path: target,
    headers: { "proxy-authorization": `Bearer ${TOKENS.use}`, ...headers },
  });
}

function judged(call = 0): ProxyTarget | undefined {
  return double.resolveForProxy.mock.calls[call]?.[2];
}

function originNamed(reply: ProxyReply): string | undefined {
  return (JSON.parse(reply.body) as { message: string }).message.split(": ").at(-1);
}

describe("a lease that names the plain reading", () => {
  it("a base-URL request reaches an http:// loopback upstream in clear", async () => {
    const reply = await send(`/127.0.0.1:${upstream.port}/user`);

    const seen = upstream.seen[0];
    expect(upstream.seen).toHaveLength(1);
    expect(seen?.headers.authorization).toBe(`Bearer ${SECRET_VALUE}`);
    expect(seen?.headers["accept-encoding"]).toBe("identity");
    expect(seen?.headers["proxy-authorization"]).toBeUndefined();

    expect(reply.status).toBe(200);
    expectAbsent(reply.raw, SECRET_VALUE);
    expect(reply.headers["x-echo"]).toBe(`Bearer ${MARKER}`);
    expect(JSON.parse(reply.body)).toMatchObject({ authorization: `Bearer ${MARKER}` });

    expect(judged()).toStrictEqual({
      method: "GET",
      origin: `https://127.0.0.1:${upstream.port}`,
      path: "/user",
      plainOrigin: `http://127.0.0.1:${upstream.port}`,
    });
    expect(double.leases[0]?.complete).toHaveBeenCalledTimes(1);
    expect(double.leases[0]?.complete).toHaveBeenCalledWith({ status: 200, sanitized: true });
  });

  it("the absolute form is served the same way", async () => {
    upstream.script((_req, res) => {
      res.writeHead(302, { location: "/next?y=1" });
      res.end();
    });
    const reply = await send(`http://127.0.0.1:${upstream.port}/user`);

    expect(upstream.seen).toHaveLength(1);
    expect(upstream.seen[0]?.headers.authorization).toBe(`Bearer ${SECRET_VALUE}`);
    expect(reply.status).toBe(302);
    expect(reply.headers.location).toBe("/next?y=1");
    expect(judged()).toStrictEqual({
      method: "GET",
      origin: `https://127.0.0.1:${upstream.port}`,
      path: "/user",
      plainOrigin: `http://127.0.0.1:${upstream.port}`,
    });
    expect(double.leases[0]?.complete).toHaveBeenCalledTimes(1);
    expect(double.leases[0]?.complete).toHaveBeenCalledWith({ status: 302, sanitized: false });
  });

  it("a dead port answers 502 naming the http:// origin", async () => {
    const dead = await deadPort();
    const reply = await send(`/127.0.0.1:${dead}/x`);

    expect(reply.status).toBe(502);
    expect(JSON.parse(reply.body)).toEqual({
      error: ErrorCode.PROXY_UPSTREAM_FAILED,
      message: `Egress proxy upstream request failed (refused): http://127.0.0.1:${dead}`,
    });
    expect(judged()?.plainOrigin).toBe(`http://127.0.0.1:${dead}`);
    expect(double.leases[0]?.complete).toHaveBeenCalledTimes(1);
    expect(double.leases[0]?.complete).toHaveBeenCalledWith({
      error: ErrorCode.PROXY_UPSTREAM_FAILED,
    });
  });

  it("a lease naming a plain reading the request lacks is a 500", async () => {
    const lease = recordingLease(SECRET_VALUE, null, true);
    double.resolveForProxy.mockResolvedValueOnce(lease);
    const reply = await send(`https://127.0.0.1:${upstream.port}/user`);

    expect(reply.status).toBe(500);
    expect(JSON.parse(reply.body)).toEqual({
      error: ErrorCode.INTERNAL_ERROR,
      message: "Internal proxy error",
    });
    expect(lease.complete).toHaveBeenCalledTimes(1);
    expect(lease.complete).toHaveBeenCalledWith({ error: ErrorCode.INTERNAL_ERROR });
    expect(errors.map((err) => [err.code, err.message])).toEqual([
      [ErrorCode.INTERNAL_ERROR, "the lease names a plain reading the request does not have"],
    ]);
    expect([...lease.value].every((byte) => byte === 0)).toBe(true);
    expect(upstream.seen).toHaveLength(0);
  });

  it("a lease naming a plain reading beside a pinned CA is a 500", async () => {
    const lease = recordingLease(SECRET_VALUE, CA.certPem, true);
    double.resolveForProxy.mockResolvedValueOnce(lease);
    const reply = await send(`/127.0.0.1:${upstream.port}/user`);

    expect(reply.status).toBe(500);
    expect(JSON.parse(reply.body)).toEqual({
      error: ErrorCode.INTERNAL_ERROR,
      message: "Internal proxy error",
    });
    expect(lease.complete).toHaveBeenCalledTimes(1);
    expect(lease.complete).toHaveBeenCalledWith({ error: ErrorCode.INTERNAL_ERROR });
    expect(errors.map((err) => [err.code, err.message])).toEqual([
      [ErrorCode.INTERNAL_ERROR, "the lease names a plain reading beside a pinned CA"],
    ]);
    expect([...lease.value].every((byte) => byte === 0)).toBe(true);
    expect(upstream.seen).toHaveLength(0);
  });
});

describe("the target handed to the engine on a loopback line", () => {
  it.each([
    ["/127.0.0.1/x", "https://127.0.0.1", "http://127.0.0.1"],
    ["/127.0.0.1:80/x", "https://127.0.0.1:80", "http://127.0.0.1"],
    ["/127.0.0.1:443/x", "https://127.0.0.1", "http://127.0.0.1:443"],
    ["/127.1:9000/x", "https://127.0.0.1:9000", "http://127.0.0.1:9000"],
    ["http://127.0.0.1:80/x", "https://127.0.0.1", "http://127.0.0.1"],
  ])("%s names %s as its origin and %s as its plain origin", async (line, origin, plainOrigin) => {
    double.resolveForProxy.mockRejectedValueOnce(VaultError.urlNotAllowed(origin));
    const reply = await send(line);

    expect(reply.status).toBe(403);
    expect(double.resolveForProxy).toHaveBeenCalledTimes(1);
    expect(judged()).toStrictEqual({ method: "GET", origin, path: "/x", plainOrigin });
    expect(upstream.seen).toHaveLength(0);
  });
});

describe("requests that have no plain reading to hand", () => {
  it("a request without a placeholder never reaches the plain fixture", async () => {
    const reply = await send(`/127.0.0.1:${upstream.port}/user`, {});

    expect(reply.status).toBe(502);
    expect(JSON.parse(reply.body)).toMatchObject({ error: ErrorCode.PROXY_UPSTREAM_FAILED });
    expect(originNamed(reply)).toBe(`https://127.0.0.1:${upstream.port}`);
    expect(double.resolveForProxy).not.toHaveBeenCalled();
    expect(upstream.seen).toHaveLength(0);
  });

  it("an https:// request line hands no plain reading", async () => {
    const reply = await send(`https://127.0.0.1:${upstream.port}/user`);

    expect(reply.status).toBe(502);
    expect(originNamed(reply)).toBe(`https://127.0.0.1:${upstream.port}`);
    expect(judged()).toStrictEqual({
      method: "GET",
      origin: `https://127.0.0.1:${upstream.port}`,
      path: "/user",
    });
    expect(upstream.seen).toHaveLength(0);
  });

  it("a tunnelled request hands no plain reading", async () => {
    const tunnel = await openTunnel({
      port,
      authority: `127.0.0.1:${upstream.port}`,
      fields: [`Proxy-Authorization: Bearer ${TOKENS.use}`],
      ca: CA.rootPem,
    });
    expect(tunnel.established.split("\r\n")[0]).toBe("HTTP/1.1 200 Connection Established");
    const answer = await exchangeInTunnel(
      tunnel.socket as TLSSocket,
      `GET /user HTTP/1.1\r\nHost: 127.0.0.1:${upstream.port}\r\n` +
        "Authorization: Bearer harpoc:gh-pat\r\nConnection: close\r\n\r\n",
    );

    expect(answer.split("\r\n")[0]).toBe("HTTP/1.1 502 Bad Gateway");
    expect(judged()).toStrictEqual({
      method: "GET",
      origin: `https://127.0.0.1:${upstream.port}`,
      path: "/user",
    });
    expect(upstream.seen).toHaveLength(0);
  });
});

describe("redirects on the plain reading (A5)", () => {
  function redirectTo(location: string): void {
    upstream.script((_req, res) => {
      res.writeHead(302, { location });
      res.end();
    });
  }

  it("a relative Location is mapped against the plain reading", async () => {
    redirectTo("/next?y=1");
    const reply = await send(`/127.0.0.1:${upstream.port}/start`);

    expect(upstream.seen).toHaveLength(1);
    expect(reply.status).toBe(302);
    expect(reply.headers.location).toBe(`/127.0.0.1:${upstream.port}/next?y=1`);
  });

  it("an absolute one on the plain origin", async () => {
    redirectTo(`http://127.0.0.1:${upstream.port}/abs`);
    const reply = await send(`/127.0.0.1:${upstream.port}/start`);

    expect(upstream.seen).toHaveLength(1);
    expect(reply.status).toBe(302);
    expect(reply.headers.location).toBe(`/127.0.0.1:${upstream.port}/abs`);
  });

  it("a Location that names port 443 keeps the port, which the TLS reading would drop", async () => {
    redirectTo("//127.0.0.1:443/n");
    const reply = await send(`/127.0.0.1:${upstream.port}/start`);

    expect(upstream.seen).toHaveLength(1);
    expect(reply.status).toBe(302);
    expect(reply.headers.location).toBe("/127.0.0.1:443/n");
  });

  it("a Location at the plain origin's default port keeps :80, whose TLS reading would be 443", async () => {
    redirectTo("http://127.0.0.1/n");
    const reply = await send(`/127.0.0.1:${upstream.port}/start`);

    expect(upstream.seen).toHaveLength(1);
    expect(reply.status).toBe(302);
    expect(reply.headers.location).toBe("/127.0.0.1:80/n");

    double.resolveForProxy.mockRejectedValueOnce(VaultError.urlNotAllowed("https://127.0.0.1:80"));
    const followUp = await send(reply.headers.location as string);

    expect(followUp.status).toBe(403);
    expect(judged(1)).toStrictEqual({
      method: "GET",
      origin: "https://127.0.0.1:80",
      path: "/n",
      plainOrigin: "http://127.0.0.1",
    });
    expect(upstream.seen).toHaveLength(1);
  });

  it("a cross-origin one is mapped and its follow-up goes back through the lease", async () => {
    const other = await startPlainUpstream();
    try {
      redirectTo(`http://127.0.0.1:${other.port}/z`);
      const reply = await send(`/127.0.0.1:${upstream.port}/start`);

      expect(reply.status).toBe(302);
      expect(reply.headers.location).toBe(`/127.0.0.1:${other.port}/z`);

      double.resolveForProxy.mockRejectedValueOnce(
        VaultError.urlNotAllowed(`https://127.0.0.1:${other.port}`),
      );
      const followUp = await send(reply.headers.location as string);

      expect(followUp.status).toBe(403);
      expect(JSON.parse(followUp.body)).toEqual({
        error: ErrorCode.URL_NOT_ALLOWED,
        message: `URL not in secret allowlist: https://127.0.0.1:${other.port}`,
      });
      expect(judged(1)).toStrictEqual({
        method: "GET",
        origin: `https://127.0.0.1:${other.port}`,
        path: "/z",
        plainOrigin: `http://127.0.0.1:${other.port}`,
      });
      expect(other.seen).toHaveLength(0);
    } finally {
      await other.close();
    }
  });
});

describe("the IPv6 loopback literal", () => {
  it("[::1] is served on its plain reading (skipped where the host cannot bind ::1)", async (ctx) => {
    let v6: PlainUpstreamFixture;
    try {
      v6 = await startPlainUpstream("::1");
    } catch (err) {
      if (!isIpv6BindUnavailable(err)) throw err;
      return ctx.skip();
    }
    try {
      const reply = await send(`/[::1]:${v6.port}/user`);

      expect(reply.status).toBe(200);
      expect(v6.seen).toHaveLength(1);
      expect(v6.seen[0]?.headers.authorization).toBe(`Bearer ${SECRET_VALUE}`);
      expect(judged()).toStrictEqual({
        method: "GET",
        origin: `https://[::1]:${v6.port}`,
        path: "/user",
        plainOrigin: `http://[::1]:${v6.port}`,
      });
    } finally {
      await v6.close();
    }
  });
});
