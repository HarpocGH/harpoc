import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Hono } from "hono";
import type { VaultEngine } from "@harpoc/core";
import { createUiRoutes } from "./ui.js";
import { createApp } from "../app.js";

let uiDir: string;
/** A real, allowlisted-extension file one level ABOVE uiDir — the traversal target. */
let outsideName: string;
let app: Hono;

const UI_CSP =
  "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

beforeAll(() => {
  uiDir = mkdtempSync(join(tmpdir(), "harpoc-ui-"));
  writeFileSync(join(uiDir, "index.html"), '<!doctype html><div id="root"></div>');
  mkdirSync(join(uiDir, "assets"));
  writeFileSync(join(uiDir, "assets", "app-abc123.js"), "export const x = 1;");
  writeFileSync(join(uiDir, "secret.vault.db"), "not-servable");
  outsideName = `${basename(uiDir)}-outside.json`;
  writeFileSync(join(uiDir, "..", outsideName), '{"leaked":true}');
  app = new Hono();
  app.route("/ui", createUiRoutes(uiDir));
});

afterAll(() => {
  rmSync(uiDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  rmSync(join(uiDir, "..", outsideName), { force: true });
});

describe("createUiRoutes", () => {
  it("serves index.html at /ui with CSP and nosniff", async () => {
    const res = await app.request("/ui");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect(res.headers.get("content-security-policy")).toBe(UI_CSP);
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(await res.text()).toContain("root");
  });

  it("serves hashed assets with immutable caching", async () => {
    const res = await app.request("/ui/assets/app-abc123.js");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/javascript");
    expect(res.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
    expect(res.headers.get("content-security-policy")).toBe(UI_CSP);
  });

  it.each(["/ui", "/ui/", "/ui/secrets", "/ui/index.html"])(
    "%s answers the whole CSP, nosniff and no-cache",
    async (path) => {
      const res = await app.request(path);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
      expect(res.headers.get("content-security-policy")).toBe(UI_CSP);
      expect(res.headers.get("x-content-type-options")).toBe("nosniff");
      expect(res.headers.get("cache-control")).toBe("no-cache");
    },
  );

  it.each(["/ui/assets%2F..%2Findex.html", "/ui/assets/..%2Findex.html"])(
    "%s — an encoded alias of index.html under assets/ — answers the shell no-cache, not immutable",
    async (path) => {
      const res = await app.request(path);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
      expect(await res.text()).toContain('<div id="root"></div>');
      expect(res.headers.get("cache-control")).toBe("no-cache");
    },
  );

  it("serves an asset reached through an encoded slash with immutable caching", async () => {
    const res = await app.request("/ui/assets%2Fapp-abc123.js");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/javascript");
    expect(res.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
  });

  it("SPA-falls-back extension-less routes to index.html", async () => {
    const res = await app.request("/ui/secrets");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
  });

  it("404s a missing asset instead of falling back", async () => {
    expect((await app.request("/ui/assets/missing.js")).status).toBe(404);
  });

  it("404s path traversal, encoded and plain", async () => {
    expect((await app.request("/ui/..%2f..%2fpackage.json")).status).toBe(404);
    expect((await app.request("/ui/../../etc/passwd")).status).toBe(404);
  });

  it("404s an encoded escape to a file that really exists outside the root", async () => {
    const res = await app.request(`/ui/..%2f${outsideName}`);
    expect(res.status).toBe(404);
    expect(await res.text()).not.toContain("leaked");
  });

  it("404s extensions outside the content-type allowlist", async () => {
    expect((await app.request("/ui/secret.vault.db")).status).toBe(404);
  });

  it("404s a malformed percent-escape instead of throwing", async () => {
    expect((await app.request("/ui/%ZZ.js")).status).toBe(404);
  });
});

describe("createApp uiDir wiring", () => {
  const engineStub = {} as VaultEngine; // createApp only stores the reference at construction

  const HOST = { host: "localhost" };

  it("mounts /ui when uiDir is set", async () => {
    const wired = createApp(engineStub, { uiDir });
    expect((await wired.request("/ui", { headers: HOST })).status).toBe(200);
  });

  it("does not mount /ui without uiDir", async () => {
    const bare = createApp(engineStub, {});
    expect((await bare.request("/ui", { headers: HOST })).status).toBe(404);
  });

  // M-P3-7 (test-review-2026-10-09): the listener's host check covers /ui —
  // the allowlist is mounted on every path, ahead of the static handler.
  it("refuses /ui to a Host outside the allowed set: 421 MISDIRECTED_REQUEST naming the parsed hostname", async () => {
    const wired = createApp(engineStub, { uiDir, allowedHostSet: new Set(["vault.example"]) });
    const res = await wired.request("/ui", { headers: { host: "evil.example:3000" } });
    expect(res.status).toBe(421);
    const body = (await res.json()) as { error: string; message: string };
    expect(body.error).toBe("MISDIRECTED_REQUEST");
    expect(body.message).toContain("the Host header names evil.example");
    expect(body.message).not.toContain("3000");
  });

  it("serves /ui's index.html to an allowed Host (the control)", async () => {
    const wired = createApp(engineStub, { uiDir, allowedHostSet: new Set(["vault.example"]) });
    const res = await wired.request("/ui", { headers: { host: "vault.example:3000" } });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('<div id="root"></div>');
  });
});
