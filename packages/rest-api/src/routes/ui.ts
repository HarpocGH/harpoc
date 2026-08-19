import { readFile } from "node:fs/promises";
import { extname, join, normalize, resolve, sep } from "node:path";
import { Hono } from "hono";
import type { Context } from "hono";

/** Extension allowlist — anything else 404s even if present in uiDir. */
const CONTENT_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json",
  ".map": "application/json",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".txt": "text/plain; charset=utf-8",
};

const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "font-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'self'",
].join("; ");

/**
 * Static handler for the built Web UI. Hand-rolled rather than an adapter
 * serve-static: the containment check below is the security boundary and must
 * not depend on process.cwd() or adapter path semantics.
 */
export function createUiRoutes(uiDir: string): Hono {
  const root = resolve(uiDir);
  const app = new Hono();

  const handler = async (c: Context): Promise<Response> => {
    const requestPath = c.req.path.replace(/^\/ui\/?/, "");
    let decoded: string;
    try {
      decoded = decodeURIComponent(requestPath);
    } catch {
      return c.notFound();
    }
    const candidate = resolve(root, normalize(decoded));
    if (candidate !== root && !candidate.startsWith(root + sep)) {
      return c.notFound();
    }

    const ext = extname(candidate);
    const isAsset = ext !== "" && candidate !== root;
    const filePath = isAsset ? candidate : join(root, "index.html");
    const contentType = CONTENT_TYPES[isAsset ? ext : ".html"];
    if (contentType === undefined) return c.notFound();

    let body: Uint8Array;
    try {
      body = new Uint8Array(await readFile(filePath));
    } catch {
      return c.notFound();
    }

    c.header("Content-Type", contentType);
    c.header("Content-Security-Policy", CSP);
    c.header("X-Content-Type-Options", "nosniff");
    c.header(
      "Cache-Control",
      isAsset && decoded.startsWith("assets/") ? "public, max-age=31536000, immutable" : "no-cache",
    );
    return c.body(body);
  };

  app.get("/", handler);
  app.get("/*", handler);
  return app;
}
