import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import type { SeenRequest, UpstreamScript } from "./upstream-server.js";

export interface PlainUpstreamFixture {
  /** `http://127.0.0.1:<port>` or `http://[::1]:<port>` */
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

/** `startUpstream()`'s twin on `node:http`: a loopback plain-HTTP upstream recording what it is sent; rejects with the listen error. */
export async function startPlainUpstream(
  host: "127.0.0.1" | "::1" = "127.0.0.1",
): Promise<PlainUpstreamFixture> {
  const seen: SeenRequest[] = [];
  let answer = OK;
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      seen.push({ method: req.method ?? "", url: req.url ?? "", headers: req.headers, body });
      answer(req, res, body);
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, host, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  const port = (server.address() as AddressInfo).port;
  return {
    origin: host === "::1" ? `http://[::1]:${port}` : `http://127.0.0.1:${port}`,
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
