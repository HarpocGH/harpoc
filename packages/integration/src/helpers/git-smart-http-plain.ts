import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

const CGI_TIMEOUT_MS = 30_000;

/** One request the fixture received. */
export interface SeenGitRequest {
  method: string;
  url: string;
  authorization: string | undefined;
}

export interface GitSmartHttp {
  port: number;
  requests: SeenGitRequest[];
  /** While on, every request carrying the credential is answered 403 `text/plain` echoing it. */
  reflect: (on: boolean) => void;
  close: () => Promise<void>;
}

/**
 * git's smart HTTP protocol over `git http-backend` as a CGI on 127.0.0.1, in
 * plain `http:` (which the vault admits on loopback) — a local copy of core's
 * `packages/core/src/injection/__fixtures__/git-smart-http.ts`
 * `startGitSmartHttp` (integration cannot import a module out of core's
 * `src/` — see the SMTP fake's header; `git-smart-http.ts` beside this file is
 * the TLS copy the egress proxy needs). Every request must carry the Basic
 * credential `user:token`; any other is answered 401, so a fetch or an
 * `ls-remote` succeeds only when the credential reached the fixture. A trimmed
 * copy: it has no `startRecorder`, and `SeenGitRequest` keeps no headers. It
 * adds `reflect`: the hostile remote that echoes the credential a request
 * carried back in an error body, which git prints as a `remote: …` line on
 * stderr.
 */
export async function startGitSmartHttp(opts: {
  git: string;
  projectRoot: string;
  user: string;
  token: string;
  env: NodeJS.ProcessEnv;
}): Promise<GitSmartHttp> {
  const requests: SeenGitRequest[] = [];
  const basic = `Basic ${Buffer.from(`${opts.user}:${opts.token}`).toString("base64")}`;
  let reflecting = false;
  const children = new Set<ChildProcess>();
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    requests.push({
      method: req.method ?? "GET",
      url: req.url ?? "/",
      authorization: req.headers.authorization,
    });
    if (req.headers.authorization !== basic) {
      res.writeHead(401, { "www-authenticate": 'Basic realm="harpoc-test"' }).end();
      return;
    }
    if (reflecting) {
      const received = Buffer.from(
        req.headers.authorization.slice("Basic ".length),
        "base64",
      ).toString("utf8");
      res.writeHead(403, { "content-type": "text/plain" }).end(`denied for ${received}\n`);
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
      timeout: CGI_TIMEOUT_MS,
      stdio: ["pipe", "pipe", "ignore"],
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
    children.add(cgi);
    cgi.on("error", fail);
    cgi.stdin.on("error", fail);
    req.pipe(cgi.stdin);
    const out: Buffer[] = [];
    cgi.stdout.on("data", (chunk: Buffer) => out.push(chunk));
    cgi.on("close", () => {
      children.delete(cgi);
      if (res.headersSent) return;
      const raw = Buffer.concat(out);
      const end = raw.indexOf("\r\n\r\n");
      if (end < 0) {
        fail();
        return;
      }
      let statusCode = 200;
      const headers: Record<string, string> = {};
      for (const line of raw.subarray(0, end).toString("latin1").split("\r\n")) {
        const colon = line.indexOf(":");
        const headerName = line.slice(0, colon).trim().toLowerCase();
        const value = line.slice(colon + 1).trim();
        if (headerName === "status") statusCode = Number.parseInt(value, 10);
        else headers[headerName] = value;
      }
      res.writeHead(statusCode, headers).end(raw.subarray(end + 4));
    });
  });
  await new Promise<void>((done, fail) => {
    server.once("error", fail);
    server.listen(0, "127.0.0.1", done);
  });
  return {
    port: (server.address() as AddressInfo).port,
    requests,
    reflect: (on) => {
      reflecting = on;
    },
    close: async () => {
      server.closeAllConnections();
      const exits = [...children].map(
        (child) =>
          new Promise<void>((done) => {
            child.once("close", () => done());
            child.kill();
          }),
      );
      await Promise.all([...exits, new Promise<void>((done) => server.close(() => done()))]);
    },
  };
}
