import { readFileSync } from "node:fs";
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from "node:http";
import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { PKI_DIR, pkiReady } from "./pki.js";

/** One request as the echo received it. `authorization` is the brokered credential: compared, never printed. */
export interface EchoRequest {
  method: string;
  path: string;
  authorization: string | undefined;
}

/** A gate on `/echo/held`: the request is answered only after `release()`. */
export interface EchoHold {
  arrived: Promise<void>;
  release(): void;
}

export interface TlsEcho {
  port: number;
  /** `https://127.0.0.1:<port>` — covered by the `echo-https` leaf's IP SAN. */
  origin: string;
  requests: EchoRequest[];
  hold(): EchoHold;
  close(): Promise<void>;
}

const MARKER_HEADER = "x-harpoc-marker";

/**
 * `credentialOf` of `fixtures/echo-https/server.mjs`, copied: the fixture is the
 * fleet container's script — it listens on import — and its `/echo` is frozen
 * (D7), so it is not refactored into a shared module.
 */
export function echoCredentialOf(headers: IncomingHttpHeaders): string {
  const auth = headers["authorization"];
  if (typeof auth === "string") {
    const match = /^(?:Bearer|Basic)\s+(.*)$/i.exec(auth);
    return match ? (match[1] ?? "") : auth;
  }
  const custom = headers["x-api-key"];
  return typeof custom === "string" ? custom : "";
}

/** The fixture's `encodings`, copied: the fleet `/echo`'s reflection set. */
export function echoEncodings(value: string): Record<string, string> {
  const bytes = Buffer.from(value, "utf8");
  return {
    raw: value,
    base64: bytes.toString("base64"),
    base64url: bytes.toString("base64url"),
    hex: bytes.toString("hex"),
    hex_upper: bytes.toString("hex").toUpperCase(),
    percent: encodeURIComponent(value),
  };
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve: () => void = () => undefined;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

function json(res: ServerResponse, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(200, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

/**
 * The fleet `echo-https` service in process (RD-B6-3), on the fixture PKI's
 * `echo-https` leaf and a free loopback port: `/echo` reflects as the fleet's
 * does (the credential raw and encoded in the body, raw in `x-echo-credential`);
 * `/echo/raw` reflects the raw credential alone, the form the proxy's
 * exact-value redactor covers (DB-8); `/echo/held` reflects nothing and waits
 * on the armed `hold()`, so a row can observe its client mid-flight; `/health`.
 */
export async function startTlsEcho(): Promise<TlsEcho> {
  if (!pkiReady()) throw new Error("fixture PKI missing — run: pnpm --filter @harpoc/e2e pki");
  const requests: EchoRequest[] = [];
  let armed: { arrive: () => void; released: Promise<void> } | undefined;
  const releases: Array<() => void> = [];

  async function answer(req: IncomingMessage, res: ServerResponse): Promise<void> {
    req.resume();
    const url = new URL(req.url ?? "/", "https://echo-https");
    const credential = echoCredentialOf(req.headers);
    const auth = req.headers["authorization"];
    requests.push({
      method: req.method ?? "",
      path: url.pathname,
      authorization: typeof auth === "string" ? auth : undefined,
    });
    const marker = req.headers[MARKER_HEADER];

    if (url.pathname === "/health") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
      return;
    }
    if (url.pathname === "/echo/held") {
      const gate = armed;
      if (gate !== undefined) {
        gate.arrive();
        await gate.released;
      }
      json(res, { path: url.pathname, method: req.method, held: gate !== undefined });
      return;
    }
    const echoed: Record<string, string> =
      credential === "" ? {} : { "x-echo-credential": credential };
    if (url.pathname === "/echo/raw") {
      json(res, { raw: credential === "" ? null : credential }, echoed);
      return;
    }
    if (url.pathname === "/echo") {
      json(
        res,
        {
          path: url.pathname,
          method: req.method,
          authorization: req.headers["authorization"] ?? null,
          query: Object.fromEntries(url.searchParams),
          marker: typeof marker === "string" ? marker : null,
          credential: credential === "" ? null : echoEncodings(credential),
        },
        { [MARKER_HEADER]: typeof marker === "string" ? marker : "", ...echoed },
      );
      return;
    }
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("not found");
  }

  const server = createServer(
    {
      cert: readFileSync(join(PKI_DIR, "out", "echo-https.crt")),
      key: readFileSync(join(PKI_DIR, "out", "echo-https.key")),
    },
    (req, res) => {
      void answer(req, res);
    },
  );
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const { port } = server.address() as AddressInfo;

  return {
    port,
    origin: `https://127.0.0.1:${String(port)}`,
    requests,
    hold(): EchoHold {
      const arrival = deferred();
      const releasing = deferred();
      const gate = { arrive: arrival.resolve, released: releasing.promise };
      armed = gate;
      const release = (): void => {
        releasing.resolve();
        if (armed === gate) armed = undefined;
      };
      releases.push(release);
      return { arrived: arrival.promise, release };
    },
    async close(): Promise<void> {
      for (const release of releases) release();
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
        server.closeAllConnections();
      });
    },
  };
}
