import { spawn } from "node:child_process";
import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

/** One request a fixture listener received. */
export interface SeenRequest {
  method: string;
  url: string;
  authorization: string | undefined;
  headers: IncomingMessage["headers"];
}

export interface Listener {
  port: number;
  requests: SeenRequest[];
  close: () => Promise<void>;
}

function record(req: IncomingMessage, into: SeenRequest[]): void {
  into.push({
    method: req.method ?? "GET",
    url: req.url ?? "/",
    authorization: req.headers.authorization ?? req.headers["proxy-authorization"],
    headers: req.headers,
  });
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((done, fail) => {
    server.once("error", fail);
    server.listen(0, "127.0.0.1", done);
  });
  return (server.address() as AddressInfo).port;
}

function closer(server: Server): () => Promise<void> {
  return () =>
    new Promise<void>((done) => {
      server.closeAllConnections();
      server.close(() => done());
    });
}

/**
 * git's smart HTTP protocol over `git http-backend` as a CGI on 127.0.0.1,
 * serving the bare repositories under `projectRoot`. Every request — upload-pack
 * and receive-pack alike — must carry the Basic credential `user:token`; any
 * other is answered 401, so a fetch or a push succeeds only when git was handed
 * the credential.
 */
export async function startGitSmartHttp(opts: {
  git: string;
  projectRoot: string;
  user: string;
  token: string;
  env: NodeJS.ProcessEnv;
}): Promise<Listener> {
  const requests: SeenRequest[] = [];
  const basic = `Basic ${Buffer.from(`${opts.user}:${opts.token}`).toString("base64")}`;
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    record(req, requests);
    if (req.headers.authorization !== basic) {
      res.writeHead(401, { "www-authenticate": 'Basic realm="harpoc-test"' }).end();
      return;
    }
    const [pathname = "/", query = ""] = (req.url ?? "/").split("?");
    let pathInfo: string;
    try {
      pathInfo = decodeURIComponent(pathname);
    } catch {
      res.writeHead(400).end();
      return;
    }
    const fail = (): void => {
      if (!res.headersSent) res.writeHead(502);
      res.end();
    };
    const cgi = spawn(opts.git, ["http-backend"], {
      env: {
        ...opts.env,
        GIT_PROJECT_ROOT: opts.projectRoot,
        GIT_HTTP_EXPORT_ALL: "1",
        PATH_INFO: pathInfo,
        QUERY_STRING: query,
        REQUEST_METHOD: req.method ?? "GET",
        CONTENT_TYPE: req.headers["content-type"] ?? "",
        REMOTE_ADDR: "127.0.0.1",
        REMOTE_USER: opts.user,
        ...(req.headers["content-length"] === undefined
          ? {}
          : { CONTENT_LENGTH: req.headers["content-length"] }),
        ...(req.headers["content-encoding"] === undefined
          ? {}
          : { HTTP_CONTENT_ENCODING: req.headers["content-encoding"] }),
        ...(req.headers["git-protocol"] === undefined
          ? {}
          : { GIT_PROTOCOL: String(req.headers["git-protocol"]) }),
      },
    });
    cgi.on("error", fail);
    cgi.stdin.on("error", fail);
    req.pipe(cgi.stdin);
    const out: Buffer[] = [];
    cgi.stdout.on("data", (chunk: Buffer) => out.push(chunk));
    cgi.on("close", () => {
      if (res.headersSent) return;
      const raw = Buffer.concat(out);
      const end = raw.indexOf("\r\n\r\n");
      if (end < 0) {
        fail();
        return;
      }
      let status = 200;
      const headers: Record<string, string> = {};
      for (const line of raw.subarray(0, end).toString("latin1").split("\r\n")) {
        const colon = line.indexOf(":");
        const name = line.slice(0, colon).trim().toLowerCase();
        const value = line.slice(colon + 1).trim();
        if (name === "status") status = Number.parseInt(value, 10);
        else headers[name] = value;
      }
      res.writeHead(status, headers).end(raw.subarray(end + 4));
    });
  });
  const port = await listen(server);
  return { port, requests, close: closer(server) };
}

/**
 * A listener that only records: every request is answered 401 with a Basic
 * challenge, so a git that reaches it — as a proxy, or as a rewritten remote —
 * retries with whatever credential it was given.
 */
export async function startRecorder(): Promise<Listener> {
  const requests: SeenRequest[] = [];
  const server = createServer((req, res) => {
    record(req, requests);
    req.resume();
    res
      .writeHead(401, {
        "www-authenticate": 'Basic realm="recorder"',
        "proxy-authenticate": 'Basic realm="recorder"',
      })
      .end();
  });
  const port = await listen(server);
  return { port, requests, close: closer(server) };
}
