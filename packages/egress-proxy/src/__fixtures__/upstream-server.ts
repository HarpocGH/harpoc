import { readFileSync } from "node:fs";
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from "node:http";
import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import * as tls from "node:tls";

/**
 * Core's fixture CA — a declared dependency of this package, so the read
 * follows the dependency graph (integration's `helpers/cert-fixtures.ts`
 * precedent). `second-ca-cert.pem` is self-signed with SAN `IP:127.0.0.1`, so a
 * loopback upstream verifies under it as the lease's `caPem`, no DNS involved.
 */
const CORE_CERTS = new URL("../../../core/src/__fixtures__/certs/", import.meta.url);
export const FIXTURE_CA_PEM = readFileSync(new URL("second-ca-cert.pem", CORE_CERTS), "utf8");
const FIXTURE_KEY_PEM = readFileSync(new URL("second-ca-key.pem", CORE_CERTS), "utf8");
/** `rsa-cert.pem` names `fixture.example.com` only — a hostname target reaches it only through a pin. */
export const HOSTNAME_CERT_PEM = readFileSync(new URL("rsa-cert.pem", CORE_CERTS), "utf8");
export const HOSTNAME_KEY_PEM = readFileSync(new URL("rsa-key.pem", CORE_CERTS), "utf8");

/** `tls.setDefaultCACertificates` exists (Node >= 22.19 / 24.5) — the pass-through rows need it. */
export const CAN_SET_DEFAULT_CA = typeof tls.setDefaultCACertificates === "function";

/**
 * A pass-through carries no lease and so no CA pin: the fixture CA joins the
 * default store for those rows (http-injector.tls.test.ts's C6 idiom). Returns
 * the restore, for the matching `afterAll`.
 */
export function trustFixtureCaByDefault(): () => void {
  const saved = tls.getCACertificates("default");
  tls.setDefaultCACertificates([...saved, FIXTURE_CA_PEM]);
  return () => tls.setDefaultCACertificates(saved);
}

export interface SeenRequest {
  method: string;
  url: string;
  headers: IncomingHttpHeaders;
  body: string;
}

/** Answers one request; the default answers `200 text/plain "ok"`. */
export type UpstreamScript = (req: IncomingMessage, res: ServerResponse, body: string) => void;

export interface UpstreamFixture {
  /** `https://127.0.0.1:<port>` */
  origin: string;
  port: number;
  /** Every request the upstream saw, in order. */
  seen: SeenRequest[];
  script(answer: UpstreamScript): void;
  close(): Promise<void>;
}

const OK: UpstreamScript = (_req, res) => {
  res.writeHead(200, { "content-type": "text/plain" });
  res.end("ok");
};

/** A loopback HTTPS upstream presenting the fixture CA's certificate, recording what it is sent. */
export async function startUpstream(): Promise<UpstreamFixture> {
  const seen: SeenRequest[] = [];
  let answer = OK;
  const server = createServer({ cert: FIXTURE_CA_PEM, key: FIXTURE_KEY_PEM }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      seen.push({ method: req.method ?? "", url: req.url ?? "", headers: req.headers, body });
      answer(req, res, body);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    origin: `https://127.0.0.1:${port}`,
    port,
    seen,
    script(next) {
      answer = next;
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  };
}

/** A loopback port nothing listens on: bound, read, closed. */
export async function deadPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}
