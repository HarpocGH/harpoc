import { createServer } from "node:http";
import type { IncomingHttpHeaders, Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import type { InjectionConfig } from "@harpoc/shared";
import { HttpInjector } from "@harpoc/core";
import { findPlaceholder } from "./placeholder.js";
import type { Placement } from "./placeholder.js";
import { swapCredential } from "./swap.js";
import type { SwapResult } from "./swap.js";
import { expectVaultError } from "@harpoc/test-utils";

const VALUE = "ghp_S3cr3tValue-xyz";
const ENCODED_VALUE = "a b+/=~é";
const bytes = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, "utf8"));
const b64 = (text: string): string => Buffer.from(text, "utf8").toString("base64");
const target = (search = ""): URL => new URL(`https://192.0.2.10/v1/user${search}`);

function placementOf(headers: IncomingHttpHeaders, url: URL): Placement {
  const scan = findPlaceholder(headers, url);
  if (scan.outcome !== "found") throw new Error(`expected one placeholder, got ${scan.outcome}`);
  return scan.match.placement;
}

function swapped(headers: IncomingHttpHeaders, url: URL, value: string): SwapResult {
  return swapCredential({ headers, url }, placementOf(headers, url), bytes(value));
}

const PLACEMENTS: [string, IncomingHttpHeaders, string][] = [
  ["bearer", { authorization: "Bearer harpoc:gh-pat" }, ""],
  ["basic_auth", { authorization: `Basic ${b64("x-access-token:harpoc:gh-pat")}` }, ""],
  ["header", { "x-api-key": "harpoc://api/gh-pat" }, ""],
  ["query", {}, "?page=2&api_key=harpoc%3Agh-pat"],
];

describe("swapCredential — the value where the placeholder stood", () => {
  it("bearer: Authorization: Bearer <value>, every other header as sent", () => {
    const result = swapped(
      { authorization: "Bearer harpoc:gh-pat", accept: "application/json" },
      target(),
      VALUE,
    );
    expect({ ...result.headers }).toEqual({
      authorization: `Bearer ${VALUE}`,
      accept: "application/json",
    });
    expect(result.url.href).toBe(target().href);
  });

  it.each(["token", "Token"])(
    "bearer under the %s scheme: Authorization: <the scheme as sent> <value>, the needle the value alone",
    (scheme) => {
      const result = swapped({ authorization: `${scheme} harpoc:gh-pat` }, target(), VALUE);
      expect({ ...result.headers }).toEqual({ authorization: `${scheme} ${VALUE}` });
      expect(result.needles.map((needle) => Buffer.from(needle).toString("utf8"))).toEqual([VALUE]);
    },
  );

  it("basic_auth: Authorization: Basic base64(<user>:<value>) with the client's own user", () => {
    const result = swapped(
      { authorization: `Basic ${b64("x-access-token:harpoc:gh-pat")}` },
      target(),
      VALUE,
    );
    expect(result.headers["authorization"]).toBe(`Basic ${b64(`x-access-token:${VALUE}`)}`);
  });

  it("header: <header_name>: <value>, every other header as sent", () => {
    const result = swapped(
      { "x-api-key": "harpoc:gh-pat", "user-agent": "curl/8.12.1" },
      target(),
      VALUE,
    );
    expect({ ...result.headers }).toEqual({ "x-api-key": VALUE, "user-agent": "curl/8.12.1" });
  });

  it("query: the parameter's value, serialized as URLSearchParams serializes it", () => {
    const result = swapped({}, target("?api_key=harpoc:gh-pat"), ENCODED_VALUE);
    expect(result.url.search).toBe("?api_key=a+b%2B%2F%3D%7E%C3%A9");
    expect(result.url.searchParams.get("api_key")).toBe(ENCODED_VALUE);
  });

  it("query: every other component of the query is forwarded byte for byte", () => {
    const result = swapped({}, target("?flag&q=a%20b&api_key=harpoc%3Agh-pat&x=~&y="), VALUE);
    expect(result.url.search).toBe(`?flag&q=a%20b&api_key=${VALUE}&x=~&y=`);
  });

  it("query: a parameter whose name begins with ? is the one the finder named, the other component as sent", () => {
    const result = swapped({}, target("?a=1&?b=harpoc%3Agh-pat"), ENCODED_VALUE);
    expect(result.url.search).toBe("?a=1&?b=a+b%2B%2F%3D%7E%C3%A9");
  });

  it.each(PLACEMENTS)(
    "%s: the placeholder is gone from every header and from the URL",
    (_label, headers, search) => {
      const result = swapped(headers, target(search), VALUE);
      const sent = JSON.stringify({ ...result.headers }) + result.url.href;
      expect(sent).not.toMatch(/harpoc(:|%3A)/i);
      expect(sent).not.toContain(b64("x-access-token:harpoc:gh-pat"));
    },
  );

  it.each(PLACEMENTS)(
    "%s: the request it was given is left as it was",
    (_label, headers, search) => {
      const before = JSON.stringify(headers);
      const url = target(search);
      swapCredential({ headers, url }, placementOf(headers, url), bytes(VALUE));
      expect(JSON.stringify(headers)).toBe(before);
      expect(url.href).toBe(target(search).href);
    },
  );

  it.each(PLACEMENTS)(
    "%s: the target's origin and path are untouched; only a query placement changes the query",
    (label, headers, search) => {
      const url = target(search);
      const result = swapped(headers, url, VALUE);
      expect(result.url.origin).toBe(url.origin);
      expect(result.url.pathname).toBe(url.pathname);
      expect(result.url.search).toBe(label === "query" ? `?page=2&api_key=${VALUE}` : url.search);
    },
  );

  it("the swapped headers are a null-prototype copy without the absent values", () => {
    const result = swapped(
      { authorization: "Bearer harpoc:k", "x-absent": undefined },
      target(),
      VALUE,
    );
    expect(Object.getPrototypeOf(result.headers)).toBeNull();
    expect(Object.keys(result.headers)).toEqual(["authorization"]);
  });
});

describe("swapCredential — the needles for the redactor: the value and its on-the-wire form", () => {
  it.each<[string, IncomingHttpHeaders, string, string, string[]]>([
    ["bearer", { authorization: "Bearer harpoc:k" }, "", VALUE, [VALUE]],
    ["header", { "x-api-key": "harpoc:k" }, "", VALUE, [VALUE]],
    [
      "basic_auth",
      { authorization: `Basic ${b64("x-access-token:harpoc:k")}` },
      "",
      VALUE,
      [VALUE, b64(`x-access-token:${VALUE}`)],
    ],
    ["query, a value the serializer leaves as it is", {}, "?api_key=harpoc:k", VALUE, [VALUE]],
    [
      "query, a value the serializer encodes",
      {},
      "?api_key=harpoc:k",
      ENCODED_VALUE,
      [ENCODED_VALUE, "a+b%2B%2F%3D%7E%C3%A9"],
    ],
  ])("%s", (_label, headers, search, value, expected) => {
    const { needles } = swapped(headers, target(search), value);
    expect(needles.map((needle) => Buffer.from(needle).toString("utf8"))).toEqual(expected);
  });

  it("each needle is the swap's own copy: zero-filling them leaves the value untouched", () => {
    const value = bytes(VALUE);
    const headers = { authorization: `Basic ${b64("u:harpoc:k")}` };
    const { needles } = swapCredential(
      { headers, url: target() },
      placementOf(headers, target()),
      value,
    );
    for (const needle of needles) needle.fill(0);
    expect(Buffer.from(value).toString("utf8")).toBe(VALUE);
  });
});

describe("swapCredential — the same bytes on the wire as the HTTP injector's placements", () => {
  let server: Server;
  let base: string;

  beforeAll(async () => {
    server = createServer((req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          authorization: req.headers["authorization"],
          apiKey: req.headers["x-api-key"],
          path: req.url,
        }),
      );
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it.each<[string, InjectionConfig, string, IncomingHttpHeaders, string, string]>([
    ["bearer", { type: "bearer" }, VALUE, { authorization: "Bearer harpoc:k" }, "", VALUE],
    [
      "header",
      { type: "header", header_name: "x-api-key" },
      VALUE,
      { "x-api-key": "harpoc:k" },
      "",
      VALUE,
    ],
    [
      "query",
      { type: "query", query_param: "api_key" },
      ENCODED_VALUE,
      {},
      "?api_key=harpoc:k",
      ENCODED_VALUE,
    ],
    [
      "basic_auth (the injector's value is <user>:<value>)",
      { type: "basic_auth" },
      `x-access-token:${VALUE}`,
      { authorization: `Basic ${b64("x-access-token:harpoc:k")}` },
      "",
      VALUE,
    ],
  ])("%s", async (_label, injection, injectorValue, headers, search, proxyValue) => {
    const response = await new HttpInjector(null).executeWithSecret(
      { method: "GET", url: `${base}/echo`, responseMode: "full" },
      bytes(injectorValue),
      injection,
    );
    const viaInjector = JSON.parse(response.body ?? "{}") as Record<string, string>;
    const url = new URL(`${base}/echo${search}`);
    const swap = swapCredential({ headers, url }, placementOf(headers, url), bytes(proxyValue));
    expect({
      authorization: swap.headers["authorization"],
      apiKey: swap.headers["x-api-key"],
      path: `${swap.url.pathname}${swap.url.search}`,
    }).toEqual(viaInjector);
  });
});

describe("swapCredential — refusals never carry the value", () => {
  const MESSAGE = "the secret value cannot be placed in a header: it contains CR, LF or NUL";

  it.each(["\r", "\n", "\0"])(
    "a value with %j is refused in the bearer placement",
    async (char) => {
      const err = await expectVaultError(
        () => swapped({ authorization: "Bearer harpoc:k" }, target(), `ghp_left${char}right`),
        ErrorCode.INVALID_INJECTION_CONFIG,
      );
      expect(err.message).toBe(MESSAGE);
    },
  );

  it("a value with LF is refused in the header placement", async () => {
    const err = await expectVaultError(
      () => swapped({ "x-api-key": "harpoc:k" }, target(), "ghp_left\nright"),
      ErrorCode.INVALID_INJECTION_CONFIG,
    );
    expect(err.message).toBe(MESSAGE);
    expect(err.message).not.toContain("ghp_left");
  });

  it("basic_auth and query carry such a value encoded (control)", () => {
    const basic = swapped({ authorization: `Basic ${b64("u:harpoc:k")}` }, target(), "a\nb");
    expect(basic.headers["authorization"]).toBe(`Basic ${b64("u:a\nb")}`);
    const query = swapped({}, target("?api_key=harpoc:k"), "a\nb");
    expect(query.url.search).toBe("?api_key=a%0Ab");
  });

  it("a query placement whose parameter holds no placeholder is refused", async () => {
    const err = await expectVaultError(
      () =>
        swapCredential(
          { headers: {}, url: target("?api_key=hunter2") },
          { type: "query", query_param: "api_key" },
          bytes(VALUE),
        ),
      ErrorCode.INVALID_INJECTION_CONFIG,
    );
    expect(err.message).toBe("query parameter api_key carries no placeholder");
    expect(err.message).not.toContain(VALUE);
  });
});
