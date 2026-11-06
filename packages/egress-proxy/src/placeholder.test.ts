import { createServer } from "node:http";
import type { IncomingHttpHeaders, Server } from "node:http";
import { connect } from "node:net";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  ErrorCode,
  MAX_NAME_LENGTH,
  formatHandle,
  injectionConfigSchema,
  isValidHandle,
} from "@harpoc/shared";
import { findPlaceholder, parsePlaceholder } from "./placeholder.js";
import type { Placeholder, PlaceholderMatch, PlaceholderScan } from "./placeholder.js";
import { expectVaultError } from "@harpoc/test-utils";

const target = (search = ""): URL => new URL(`https://192.0.2.10/v1/user${search}`);
const basic = (credentials: Buffer | string): string =>
  `Basic ${Buffer.from(credentials).toString("base64")}`;

function matchOf(scan: PlaceholderScan): PlaceholderMatch {
  if (scan.outcome !== "found") throw new Error(`expected one placeholder, got ${scan.outcome}`);
  return scan.match;
}

describe("parsePlaceholder — harpoc:<name> and harpoc://<project>/<name> (B2-U1)", () => {
  it.each([
    ["harpoc:gh-pat", { name: "gh-pat", handle: "secret://gh-pat", raw: "harpoc:gh-pat" }],
    ["harpoc:A_z-09", { name: "A_z-09", handle: "secret://A_z-09", raw: "harpoc:A_z-09" }],
    [
      "harpoc://api/gh-pat",
      { project: "api", name: "gh-pat", handle: "secret://api/gh-pat", raw: "harpoc://api/gh-pat" },
    ],
    [
      "harpoc://P_1/n-2",
      { project: "P_1", name: "n-2", handle: "secret://P_1/n-2", raw: "harpoc://P_1/n-2" },
    ],
    [
      "harpoc:__proto__",
      { name: "__proto__", handle: "secret://__proto__", raw: "harpoc:__proto__" },
    ],
  ])("accepts %s", (text, expected) => {
    expect(parsePlaceholder(text)).toStrictEqual(expected);
  });

  it.each([
    "",
    "harpoc",
    "harpoc:",
    "harpoc://",
    "harpoc://x",
    "harpoc://x/",
    "harpoc:///x",
    "harpoc:/x",
    "harpoc:a/b",
    "harpoc://a/b/c",
    "Harpoc:name",
    "HARPOC:name",
    "harpoc:name ",
    " harpoc:name",
    "harpoc:name\n",
    "harpoc:na me",
    "harpoc:na.me",
    "harpoc:na%2Dme",
    "harpoc:näme",
    "harpoc:a,harpoc:b",
    "harpoc:name;x",
    "xharpoc:name",
    "secret://name",
  ])("refuses %j", (text) => {
    expect(parsePlaceholder(text)).toBeNull();
  });

  it.each(["a", "Z9", "_", "-", "a-b_c", "a.b", "a b", "a%20b", "ä", "", "a:b", "a\u0000"])(
    "the segment %j is accepted exactly where isValidHandle accepts it",
    (segment) => {
      expect(parsePlaceholder(`harpoc:${segment}`) !== null).toBe(
        isValidHandle(`secret://${segment}`),
      );
      expect(parsePlaceholder(`harpoc://${segment}/n`) !== null).toBe(
        isValidHandle(`secret://${segment}/n`),
      );
    },
  );

  it.each(["harpoc:gh-pat", "harpoc://api/gh-pat", "harpoc:__proto__"])(
    "%s: the handle is the one formatHandle builds from the same segments",
    (text) => {
      const { name, project, handle } = parsePlaceholder(text) as Placeholder;
      expect(handle).toBe(formatHandle(name, project));
    },
  );

  it("a name past MAX_NAME_LENGTH is still a placeholder: the grammar is isValidHandle's, which has no length cap, and the engine answers it as an unknown handle", async () => {
    const name = "a".repeat(MAX_NAME_LENGTH + 1);
    expect(parsePlaceholder(`harpoc:${name}`)?.handle).toBe(`secret://${name}`);
    await expectVaultError(() => formatHandle(name), ErrorCode.INVALID_SECRET_NAME);
  });
});

describe("findPlaceholder — the four positions", () => {
  it("Authorization: Bearer <placeholder> derives the bearer placement", () => {
    expect(findPlaceholder({ authorization: "Bearer harpoc:gh-pat" }, target())).toStrictEqual({
      outcome: "found",
      match: {
        placeholder: { name: "gh-pat", handle: "secret://gh-pat", raw: "harpoc:gh-pat" },
        placement: { type: "bearer" },
      },
    });
  });

  it.each(["bearer harpoc:k", "BEARER harpoc:k", "Bearer   harpoc://p/k"])(
    "the Bearer scheme is case-insensitive and takes one or more spaces: %j",
    (authorization) => {
      expect(matchOf(findPlaceholder({ authorization }, target())).placement).toEqual({
        type: "bearer",
      });
    },
  );

  it.each([
    "Bearer harpoc:k extra",
    "Bearer\tharpoc:k",
    "Bearerharpoc:k",
    "Bearer xharpoc:k",
    "Bearer harpoc:k,harpoc:j",
    "Token harpoc:k",
  ])("not a placeholder: Authorization %j", (authorization) => {
    expect(findPlaceholder({ authorization }, target())).toEqual({ outcome: "none" });
  });

  it("Authorization: Basic base64(<user>:<placeholder>) derives basic_auth and keeps the client's user", () => {
    const match = matchOf(
      findPlaceholder({ authorization: basic("x-access-token:harpoc:gh-pat") }, target()),
    );
    expect(match).toStrictEqual({
      placeholder: { name: "gh-pat", handle: "secret://gh-pat", raw: "harpoc:gh-pat" },
      placement: { type: "basic_auth", user: "x-access-token" },
    });
  });

  it("an empty basic-auth user is kept as the empty string", () => {
    const match = matchOf(findPlaceholder({ authorization: basic(":harpoc:k") }, target()));
    expect(match.placement).toEqual({ type: "basic_auth", user: "" });
  });

  it.each([
    ["the placeholder as the user", basic("harpoc:k:hunter2")],
    ["a password that is not a placeholder", basic("user:hunter2")],
    ["a password holding the placeholder inside", basic("user:xharpoc:k")],
    ["no colon", basic("harpoc-k")],
    ["undecodable base64", "Basic !!!!"],
    ["unpadded base64", basic("u:harpoc:k").replace(/=+$/, "")],
    ["credentials that are not UTF-8", basic(Buffer.from([0xff, 0x3a, 0x68]))],
    ["text after the token", `${basic("u:harpoc:k")} x`],
  ])("not a placeholder: Basic with %s", (_label, authorization) => {
    expect(findPlaceholder({ authorization }, target())).toEqual({ outcome: "none" });
  });

  it("any other header whose whole value is a placeholder derives a header placement under its name", () => {
    const match = matchOf(
      findPlaceholder({ accept: "application/json", "x-api-key": "harpoc:k" }, target()),
    );
    expect(match.placement).toEqual({ type: "header", header_name: "x-api-key" });
    expect(injectionConfigSchema.safeParse(match.placement).success).toBe(true);
  });

  it("an Authorization value that is only the placeholder is a header placement", () => {
    const match = matchOf(findPlaceholder({ authorization: "harpoc:k" }, target()));
    expect(match.placement).toEqual({ type: "header", header_name: "authorization" });
  });

  it.each<[string, IncomingHttpHeaders]>([
    ["inside a longer value", { "x-api-key": "key=harpoc:k" }],
    ["as node joins a duplicated header", { "x-api-key": "harpoc:k, harpoc:j" }],
    ["under a name the injection config refuses", { "x-api.key": "harpoc:k" }],
    ["as an array value", { "set-cookie": ["harpoc:k"] }],
    ["as an absent value", { "x-api-key": undefined }],
  ])("not a placeholder: a header %s", (_label, headers) => {
    expect(findPlaceholder(headers, target())).toEqual({ outcome: "none" });
  });

  it.each([
    "host",
    "proxy-authorization",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "transfer-encoding",
    "upgrade",
    "content-length",
  ])("a placeholder in %s is not a position — the forwarder drops or rewrites it", (name) => {
    expect(findPlaceholder({ [name]: "harpoc:k" }, target())).toEqual({ outcome: "none" });
  });

  it("a query parameter whose whole value is a placeholder derives a query placement", () => {
    const match = matchOf(findPlaceholder({}, target("?page=2&token=harpoc:k")));
    expect(match.placement).toEqual({ type: "query", query_param: "token" });
    expect(injectionConfigSchema.safeParse(match.placement).success).toBe(true);
  });

  it.each(["?token=harpoc%3Ak", "?token=harpoc%3A%2F%2Fp%2Fk", "?token=harpoc://p/k"])(
    "a query placeholder is read as URLSearchParams decodes it: %s",
    (search) => {
      const match = matchOf(findPlaceholder({}, target(search)));
      expect(match.placement).toEqual({ type: "query", query_param: "token" });
    },
  );

  it("a __proto__ parameter is a query placement — a URLSearchParams name, never an object key", () => {
    const match = matchOf(findPlaceholder({}, target("?__proto__=harpoc:k")));
    expect(match.placement).toEqual({ type: "query", query_param: "__proto__" });
  });

  it.each([
    ["under an empty name", target("?=harpoc:k")],
    ["inside a longer value", target("?q=xharpoc:k")],
    ["as the parameter name", target("?harpoc:k=1")],
    ["in a path segment", new URL("https://192.0.2.10/harpoc:k/repos")],
  ])("not a placeholder: the query or URL %s", (_label, url) => {
    expect(findPlaceholder({}, url)).toEqual({ outcome: "none" });
  });

  it("a request without any placeholder is none", () => {
    expect(
      findPlaceholder({ authorization: "Bearer ghp_real", accept: "*/*" }, target("?q=1")),
    ).toEqual({ outcome: "none" });
  });

  it.each<[string, IncomingHttpHeaders, string]>([
    ["two headers", { authorization: "Bearer harpoc:a", "x-api-key": "harpoc:b" }, ""],
    ["a header and a query parameter", { "x-api-key": "harpoc:a" }, "?token=harpoc:a"],
    ["two query parameters", {}, "?a=harpoc:a&b=harpoc:b"],
    ["one query parameter twice", {}, "?token=harpoc:a&token=harpoc:a"],
  ])("%s → multiple, before any resolution (R-P1)", (_label, headers, search) => {
    expect(findPlaceholder(headers, target(search))).toEqual({ outcome: "multiple" });
  });
});

describe("findPlaceholder on the headers node:http delivers", () => {
  let server: Server;
  let port: number;
  let deliver: ((headers: IncomingHttpHeaders) => void) | undefined;

  beforeAll(async () => {
    server = createServer((req, res) => {
      deliver?.(req.headers);
      res.end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    port = (server.address() as AddressInfo).port;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  function headersFor(lines: string[]): Promise<IncomingHttpHeaders> {
    return new Promise((resolve, reject) => {
      const socket = connect(port, "127.0.0.1");
      socket.setTimeout(5_000, () => {
        socket.destroy();
        reject(new Error("the loopback server saw no request within 5 s"));
      });
      deliver = (headers) => {
        deliver = undefined;
        socket.destroy();
        resolve(headers);
      };
      socket.on("error", reject);
      socket.write(
        ["GET /v1/user HTTP/1.1", "Host: 127.0.0.1", ...lines, "Connection: close", "", ""].join(
          "\r\n",
        ),
      );
    });
  }

  it("a mixed-case header name arrives lowercased, so header_name is x-api-key", async () => {
    const headers = await headersFor(["X-Api-Key: harpoc:k"]);
    expect(matchOf(findPlaceholder(headers, target())).placement).toEqual({
      type: "header",
      header_name: "x-api-key",
    });
  });

  it("optional whitespace around the value is the parser's to trim", async () => {
    const headers = await headersFor(["X-Api-Key:    harpoc:k   "]);
    expect(matchOf(findPlaceholder(headers, target())).placeholder.raw).toBe("harpoc:k");
  });

  it("a duplicated header arrives joined and is not a placeholder", async () => {
    const headers = await headersFor(["X-Api-Key: harpoc:k", "X-Api-Key: harpoc:j"]);
    expect(findPlaceholder(headers, target())).toEqual({ outcome: "none" });
  });

  it("a duplicated Authorization arrives as its first value alone", async () => {
    const headers = await headersFor([
      "Authorization: Bearer harpoc:a",
      "Authorization: Bearer harpoc:b",
    ]);
    expect(matchOf(findPlaceholder(headers, target())).placeholder.raw).toBe("harpoc:a");
  });

  it("a __proto__ request header never reaches req.headers", async () => {
    const headers = await headersFor(["__proto__: harpoc:k"]);
    expect(findPlaceholder(headers, target())).toEqual({ outcome: "none" });
  });
});
