import { createServer } from "node:http";
import type { Server } from "node:http";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterAll, afterEach, beforeAll, beforeEach } from "vitest";
import { VaultEngine } from "../vault-engine.js";

/** One request the token endpoint received: its auth and accept headers and parsed form body. */
export interface TokenRequest {
  authorization: string | undefined;
  accept: string | undefined;
  body: URLSearchParams;
}

/**
 * A fresh, initialized engine per test and one loopback token endpoint per
 * file that records every request and answers `response`. While `gate` is set
 * the endpoint holds each answer until it settles, so concurrent callers can
 * be observed joining one in-flight request; `onRequest`, when set, is called
 * as each request is recorded, so a test can act while that answer is held.
 */
export interface OAuthEngineContext {
  engine: VaultEngine;
  dbPath: string;
  tokenEndpoint: string;
  requests: TokenRequest[];
  response: { status: number; body: unknown };
  gate: Promise<void> | undefined;
  onRequest: (() => void) | undefined;
}

export function useOAuthEngine(): OAuthEngineContext {
  const ctx = { requests: [] as TokenRequest[] } as OAuthEngineContext;
  let server: Server | undefined;
  let tempDir = "";

  beforeAll(async () => {
    const listening = createServer((req, res) => {
      let data = "";
      req.on("data", (chunk: Buffer) => {
        data += chunk.toString("utf8");
      });
      req.on("end", () => {
        ctx.requests.push({
          authorization: req.headers.authorization,
          accept: req.headers.accept,
          body: new URLSearchParams(data),
        });
        ctx.onRequest?.();
        const { status, body } = ctx.response;
        void (ctx.gate ?? Promise.resolve()).then(() => {
          res.writeHead(status, { "Content-Type": "application/json" });
          res.end(JSON.stringify(body));
        });
      });
    });
    server = listening;
    await new Promise<void>((resolve) => listening.listen(0, "127.0.0.1", () => resolve()));
    ctx.tokenEndpoint = `http://127.0.0.1:${(listening.address() as { port: number }).port}`;
  });

  afterAll(async () => {
    const listening = server;
    if (!listening) return;
    listening.closeAllConnections();
    await new Promise<void>((resolve) => listening.close(() => resolve()));
  });

  beforeEach(async () => {
    tempDir = join(
      tmpdir(),
      `harpoc-oauth-c2-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    mkdirSync(tempDir, { recursive: true });
    ctx.dbPath = join(tempDir, "test.vault.db");
    ctx.engine = new VaultEngine({
      dbPath: ctx.dbPath,
      sessionPath: join(tempDir, "session.json"),
    });
    ctx.requests = [];
    ctx.response = {
      status: 200,
      body: { access_token: "S3CRET-TOKEN-renewed", expires_in: 3600 },
    };
    ctx.gate = undefined;
    ctx.onRequest = undefined;
    await ctx.engine.initVault("password");
  });

  afterEach(async () => {
    await ctx.engine.destroy();
    rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  return ctx;
}

/** Run one statement against the vault database out of band (a fixture write). */
export function runSql(dbPath: string, sql: string, ...params: unknown[]): number {
  const db = new Database(dbPath);
  try {
    return db.prepare(sql).run(...params).changes;
  } finally {
    db.close();
  }
}

/** Read one row from the vault database out of band. */
export function readRow(dbPath: string, sql: string, ...params: unknown[]): unknown {
  const db = new Database(dbPath, { readonly: true });
  try {
    return db.prepare(sql).get(...params);
  } finally {
    db.close();
  }
}
