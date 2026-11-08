import type { IncomingHttpHeaders } from "node:http";
import { request } from "node:https";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { caPem } from "./pki.js";
import { startTlsEcho } from "./tls-echo.js";
import type { TlsEcho } from "./tls-echo.js";

interface Answer {
  status: number;
  headers: IncomingHttpHeaders;
  body: string;
}

/** A GET verified against the fixture CA alone, addressed by the certificate's IP SAN. */
function get(echo: TlsEcho, path: string, headers: Record<string, string> = {}): Promise<Answer> {
  return new Promise((resolve, reject) => {
    const req = request(
      { host: "127.0.0.1", port: echo.port, path, method: "GET", headers, ca: caPem() },
      (res) => {
        let body = "";
        res.on("data", (chunk: Buffer) => (body += chunk.toString("utf8")));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
      },
    );
    req.on("error", reject);
    req.setTimeout(10_000, () => req.destroy(new Error(`GET ${path} timed out`)));
    req.end();
  });
}

/**
 * The in-process TLS echo the model-B proxy rows broker to (RD-B6-3): the fleet
 * `echo-https` service's `/echo` reflection, served from the fixture PKI's
 * `echo-https` leaf on a loopback port, plus the two paths the rows add.
 */
describe("the in-process TLS echo", () => {
  let echo: TlsEcho;
  const credential = "b6-echo-credential-1";

  beforeAll(async () => {
    echo = await startTlsEcho();
  });

  afterAll(async () => {
    await echo?.close();
  });

  it("reflects the credential on /echo in the fleet fixture's encodings, in the body and the x-echo-credential header", async () => {
    const answer = await get(echo, "/echo", {
      authorization: `Bearer ${credential}`,
      "x-harpoc-marker": "b6-marker-1",
    });
    expect(answer.status).toBe(200);
    const body = JSON.parse(answer.body) as {
      marker: string | null;
      credential: Record<string, string> | null;
    };
    const bytes = Buffer.from(credential, "utf8");
    const reflected = {
      raw: credential,
      base64: bytes.toString("base64"),
      base64url: bytes.toString("base64url"),
      hex: bytes.toString("hex"),
      hex_upper: bytes.toString("hex").toUpperCase(),
      percent: encodeURIComponent(credential),
    };
    // Boolean-shaped throughout: a failing comparison never echoes the credential.
    expect(JSON.stringify(body.credential) === JSON.stringify(reflected)).toBe(true);
    expect(body.marker).toBe("b6-marker-1");
    expect(answer.headers["x-echo-credential"] === credential).toBe(true);
  });

  it("reflects the raw credential alone on /echo/raw, in the body and the header", async () => {
    const answer = await get(echo, "/echo/raw", { authorization: `Bearer ${credential}` });
    expect(answer.status).toBe(200);
    expect(answer.body === JSON.stringify({ raw: credential })).toBe(true);
    expect(answer.headers["x-echo-credential"] === credential).toBe(true);
  });

  it("holds /echo/held until released, and its answer reflects nothing", async () => {
    const hold = echo.hold();
    let answered = false;
    const pending = get(echo, "/echo/held", { authorization: `Bearer ${credential}` }).then(
      (answer) => {
        answered = true;
        return answer;
      },
    );
    await hold.arrived;
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(answered).toBe(false);
    hold.release();
    const answer = await pending;
    expect(answer.body === JSON.stringify({ path: "/echo/held", method: "GET", held: true })).toBe(
      true,
    );
    expect(answer.body.includes(credential)).toBe(false);
    expect(JSON.stringify(answer.headers).includes(credential)).toBe(false);
  });

  it("answers /echo/held at once where no hold is armed", async () => {
    const answer = await get(echo, "/echo/held");
    expect(JSON.parse(answer.body)).toEqual({ path: "/echo/held", method: "GET", held: false });
  });

  it("records each request's path and the Authorization header it received", async () => {
    const before = echo.requests.length;
    await get(echo, "/health", { authorization: `Bearer ${credential}` });
    const recorded = echo.requests.slice(before);
    expect(recorded.map((r) => `${r.method} ${r.path}`)).toEqual(["GET /health"]);
    expect(recorded[0]?.authorization === `Bearer ${credential}`).toBe(true);
  });
});
