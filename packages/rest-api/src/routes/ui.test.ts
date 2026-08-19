import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { describe, it, expect, beforeAll } from "vitest";
import { Hono } from "hono";
import type { VaultEngine } from "@harpoc/core";
import { createUiRoutes } from "./ui.js";
import { createApp } from "../app.js";

let uiDir: string;
/** A real, allowlisted-extension file one level ABOVE uiDir — the traversal target. */
let outsideName: string;
let app: Hono;

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

describe("createUiRoutes", () => {
  it("serves index.html at /ui with CSP and nosniff", async () => {
    const res = await app.request("/ui");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect(res.headers.get("content-security-policy")).toContain("default-src 'self'");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(await res.text()).toContain("root");
  });

  it("serves hashed assets with immutable caching", async () => {
    const res = await app.request("/ui/assets/app-abc123.js");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/javascript");
    expect(res.headers.get("cache-control")).toContain("immutable");
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

  it("mounts /ui when uiDir is set", async () => {
    const wired = createApp(engineStub, { uiDir });
    expect((await wired.request("/ui")).status).toBe(200);
  });

  it("does not mount /ui without uiDir", async () => {
    const bare = createApp(engineStub, {});
    expect((await bare.request("/ui")).status).toBe(404);
  });
});
