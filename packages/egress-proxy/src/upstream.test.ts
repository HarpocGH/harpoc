import { createServer } from "node:https";
import type { Server } from "node:https";
import type { AddressInfo } from "node:net";
import { text } from "node:stream/consumers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Agent } from "undici";
import {
  failureClass,
  forwardUpstream,
  mapLocation,
  parseTarget,
  redactText,
  relayResponseHeaders,
  upstreamRequestHeaders,
} from "./upstream.js";
import type { ParsedTarget } from "./upstream.js";
import { SECRET_VALUE } from "./__fixtures__/engine-double.js";
import { HOSTNAME_CERT_PEM, HOSTNAME_KEY_PEM, deadPort } from "./__fixtures__/upstream-server.js";

const needle = (text: string): Uint8Array => new Uint8Array(Buffer.from(text));

function target(requestUrl: string): ParsedTarget {
  const parsed = parseTarget(requestUrl);
  if (!parsed.ok) throw new Error(`refused: ${requestUrl}`);
  return parsed.target;
}

describe("parseTarget", () => {
  it.each([
    ["/api.github.com/user?x=1", "https://api.github.com/user?x=1", "path"],
    ["/api.github.com", "https://api.github.com/", "path"],
    ["/api.github.com?x=1", "https://api.github.com/?x=1", "path"],
    ["/api.github.com:8443/a", "https://api.github.com:8443/a", "path"],
    ["/api.github.com:443/a", "https://api.github.com/a", "path"],
    ["/[::1]:8443/a", "https://[::1]:8443/a", "path"],
    ["/api.github.com//evil.example/x", "https://api.github.com//evil.example/x", "path"],
    ["http://api.github.com/user", "https://api.github.com/user", "absolute-http"],
    ["http://api.github.com:80/user", "https://api.github.com/user", "absolute-http"],
    ["http://api.github.com:8443/user", "https://api.github.com:8443/user", "absolute-http"],
    ["https://api.github.com/user?x=1", "https://api.github.com/user?x=1", "absolute-https"],
  ])("%s → %s (%s)", (requestUrl, url, form) => {
    expect(parseTarget(requestUrl)).toEqual({ ok: true, target: { url: new URL(url), form } });
  });

  it.each([
    "",
    "/",
    "//api.github.com/x",
    "/a@b.example/x",
    "/a b/x",
    "/api.github.com:99999/x",
    "*",
    "ftp://api.github.com/x",
    "http://user:pw@api.github.com/x",
  ])("refuses %j", (requestUrl) => {
    expect(parseTarget(requestUrl)).toEqual({
      ok: false,
      message:
        "Not a proxy request target: send http://<proxy>/<host>[:<port>]/<path> or an absolute http:// or https:// URI",
    });
  });
});

describe("upstreamRequestHeaders", () => {
  it("removes the hop-by-hop fields, the proxy's credential, Host, Expect and every Connection option", () => {
    expect(
      upstreamRequestHeaders({
        connection: "keep-alive, X-Hop",
        "x-hop": "1",
        "keep-alive": "timeout=5",
        "proxy-connection": "Keep-Alive",
        "proxy-authorization": "Bearer t",
        te: "trailers",
        trailer: "x",
        "transfer-encoding": "chunked",
        upgrade: "h2c",
        expect: "100-continue",
        host: "127.0.0.1:3128",
        authorization: "Bearer harpoc:gh-pat",
        "accept-encoding": "gzip",
        "set-cookie": ["a=1", "b=2"],
      }),
    ).toEqual({
      authorization: "Bearer harpoc:gh-pat",
      "accept-encoding": "gzip",
      "set-cookie": ["a=1", "b=2"],
    });
  });
});

describe("redactText", () => {
  it("replaces every occurrence, the leftmost longest needle first", () => {
    expect(redactText("a-VALUE-b-VALUEX", [needle("VALUE"), needle("VALUEX")], "utf8")).toEqual({
      text: "a-[REDACTED]-b-[REDACTED]",
      changed: true,
    });
  });

  it("matches a UTF-8 value inside a latin1-decoded header value", () => {
    const value = "pässwört";
    const header = Buffer.from(`token=${value}`, "utf8").toString("latin1");
    expect(redactText(header, [needle(value)], "latin1")).toEqual({
      text: "token=[REDACTED]",
      changed: true,
    });
  });

  it("leaves text without a needle unchanged and reports no change", () => {
    expect(redactText("nothing here", [needle("VALUE"), new Uint8Array()], "utf8")).toEqual({
      text: "nothing here",
      changed: false,
    });
  });
});

describe("mapLocation", () => {
  const path = target("/api.github.com/repos/a/b");
  const absHttp = target("http://api.github.com/repos/a/b");
  const absHttps = target("https://api.github.com/repos/a/b");
  const pathWithQuery = target("/api.github.com/q?token=harpoc:gh-pat&x=1");

  it.each([
    [path, "https://api.github.com/repos/c/d", "/api.github.com/repos/c/d"],
    [path, "https://other.example/x?y=1", "/other.example/x?y=1"],
    [path, "/login?next=1", "/api.github.com/login?next=1"],
    [path, "https://objects.example:8443/o?x=1#frag", "/objects.example:8443/o?x=1"],
    [path, "http://plain.example/x", "/plain.example/x"],
    [path, "mailto:a@b.example", "mailto:a@b.example"],
    [absHttp, "https://other.example/x?y=1", "https://other.example/x?y=1"],
    [absHttp, "/login", "/login"],
    [absHttps, "https://other.example/x?y=1", "https://other.example/x?y=1"],
    [pathWithQuery, "", "/api.github.com/q?token=harpoc:gh-pat&x=1"],
    [pathWithQuery, "#frag", "/api.github.com/q?token=harpoc:gh-pat&x=1"],
  ])("maps the Location of row %#", (from, location, mapped) => {
    expect(mapLocation(location, from)).toBe(mapped);
  });
});

describe("relayResponseHeaders", () => {
  const path = target("/api.github.com/user");
  const upstreamHeaders = {
    connection: "keep-alive, x-hop",
    "x-hop": "1",
    "keep-alive": "timeout=5",
    "transfer-encoding": "chunked",
    trailer: "x",
    "proxy-authenticate": 'Basic realm="upstream"',
    "content-length": "42",
    "content-type": "text/plain",
    "set-cookie": ["a=VALUE", "b=2"],
    location: "https://api.github.com/cb?code=VALUE",
  };

  it("brokered: drops the hop-by-hop fields and Content-Length, redacts every value, maps Location", () => {
    expect(relayResponseHeaders(upstreamHeaders, path, [needle("VALUE")])).toEqual({
      headers: {
        "content-type": "text/plain",
        "set-cookie": ["a=[REDACTED]", "b=2"],
        location: "/api.github.com/cb?code=[REDACTED]",
      },
      changed: true,
    });
  });

  it("brokered on an absolute-form request: Location as sent, its value redacted", () => {
    const absolute = target("http://api.github.com/user");
    expect(
      relayResponseHeaders({ location: "https://other.example/cb?code=VALUE" }, absolute, [
        needle("VALUE"),
      ]),
    ).toEqual({ headers: { location: "https://other.example/cb?code=[REDACTED]" }, changed: true });
  });

  it("brokered: a Location the target's own query fills in is redacted after the mapping", () => {
    const swapped: ParsedTarget = {
      ...target("/127.0.0.1:4443/q?token=harpoc:gh-pat&x=1"),
      url: new URL(`https://127.0.0.1:4443/q?token=${SECRET_VALUE}&x=1`),
    };
    expect(relayResponseHeaders({ location: "" }, swapped, [needle(SECRET_VALUE)])).toEqual({
      headers: { location: "/127.0.0.1:4443/q?token=[REDACTED]&x=1" },
      changed: true,
    });
  });

  it("brokered: a Location value is redacted before the mapping can re-encode it", () => {
    expect(
      relayResponseHeaders({ location: "https://other.example/cb?code=VAL UE" }, path, [
        needle("VAL UE"),
      ]),
    ).toEqual({ headers: { location: "/other.example/cb?code=[REDACTED]" }, changed: true });
  });

  it("pass-through: keeps Content-Length and every value as sent", () => {
    expect(relayResponseHeaders(upstreamHeaders, path, null)).toEqual({
      headers: {
        "content-length": "42",
        "content-type": "text/plain",
        "set-cookie": ["a=VALUE", "b=2"],
        location: "/api.github.com/cb?code=VALUE",
      },
      changed: false,
    });
  });
});

describe("forwardUpstream", () => {
  // The certificate names fixture.example.com only: the request verifies a
  // real hostname, so it can only succeed through the pinned lookup (no DNS).
  let server: Server;
  let serverPort: number;
  const seenHosts: string[] = [];

  beforeAll(async () => {
    server = createServer({ cert: HOSTNAME_CERT_PEM, key: HOSTNAME_KEY_PEM }, (req, res) => {
      seenHosts.push(req.headers.host ?? "");
      res.end("pinned");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    serverPort = (server.address() as AddressInfo).port;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections();
    });
  });

  const budgets = { timeoutMs: 5_000, bodyIdleTimeoutMs: 5_000 };

  it("connects a hostname to the pinned address, verifies it under caPem, and the dispatcher is gone after release", async () => {
    const dispatchers = new Set<Agent>();
    const response = await forwardUpstream({
      url: new URL(`https://fixture.example.com:${serverPort}/x`),
      method: "GET",
      headers: {},
      body: null,
      resolvedAddresses: ["127.0.0.1"],
      caPem: HOSTNAME_CERT_PEM,
      dispatchers,
      ...budgets,
    });
    expect(response.statusCode).toBe(200);
    expect(await text(response.body)).toBe("pinned");
    expect(seenHosts.at(-1)).toBe(`fixture.example.com:${serverPort}`);
    expect(dispatchers.size).toBe(1);
    await response.release();
    expect(dispatchers.size).toBe(0);
  });

  it("a refused connect rejects and leaves no dispatcher behind", async () => {
    const dispatchers = new Set<Agent>();
    const dead = await deadPort();
    let thrown: unknown;
    try {
      await forwardUpstream({
        url: new URL(`https://127.0.0.1:${dead}/x`),
        method: "GET",
        headers: {},
        body: null,
        dispatchers,
        ...budgets,
      });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toMatchObject({ code: "ECONNREFUSED" });
    expect(dispatchers.size).toBe(0);
  });
});

describe("failureClass", () => {
  it.each([
    ["refused", ["ECONNREFUSED", "ECONNRESET", "ENOTFOUND", "EHOSTUNREACH", "ENETUNREACH"]],
    [
      "timeout",
      ["UND_ERR_CONNECT_TIMEOUT", "UND_ERR_HEADERS_TIMEOUT", "UND_ERR_BODY_TIMEOUT", "ETIMEDOUT"],
    ],
    [
      "tls",
      [
        "DEPTH_ZERO_SELF_SIGNED_CERT",
        "SELF_SIGNED_CERT_IN_CHAIN",
        "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
        "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
        "CERT_HAS_EXPIRED",
        "ERR_TLS_CERT_ALTNAME_INVALID",
        "EPROTO",
      ],
    ],
  ])(
    "names the %s class by the error's code alone; an unknown or absent code is undefined",
    (reason, codes) => {
      for (const code of codes) {
        expect(failureClass(Object.assign(new Error("upstream failed"), { code }))).toBe(reason);
      }
      const text = codes.join(" ");
      expect(failureClass(Object.assign(new Error(text), { code: "E_UNLISTED" }))).toBeUndefined();
      expect(failureClass(new Error(text))).toBeUndefined();
      expect(failureClass(null)).toBeUndefined();
      expect(failureClass(undefined)).toBeUndefined();
    },
  );
});
