import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer } from "node:http";
import type { Server } from "node:http";
import { startBaselineServer } from "../arms/baseline.js";
import type { BaselineServer } from "../arms/baseline.js";
import { sinkSawCredential } from "./attacker.js";
import type { SinkRequest } from "./attacker.js";

/**
 * The behavioural counterpart to `fixtures.test.ts`'s source-text pin (F2).
 *
 * That pin reads the fixture's dispatch expressions and asserts the vault's
 * field names appear in them. It is a text check: it cannot tell whether the
 * credential actually lands in the header the caller named, and the review of
 * 2026-08-14 recorded exactly that gap when the historical `?? "x-api-key"`
 * fallback survived a green suite. So this file spawns the fixture, drives it
 * over MCP as the arms do, and observes where the credential arrives — with a
 * RENAMED header as the discriminating case: only a fixture that honours the
 * caller-supplied name can move it.
 *
 * Fleet-free by construction. The baseline is a spawned Node process, not a
 * container, and the sink is an in-process `node:http` recorder on loopback
 * over plain HTTP — no Docker, no fixture CA, no `assertFleetUp`, so this runs
 * on a Windows development host between fleet runs.
 */
const CREDENTIAL = "baseline-behavior-credential-4b7e";
const HANDLE = "secret://baseline-behavior";

/**
 * `SinkRequest`-shaped records from the containerised attacker sink's
 * in-process twin — the same shape, so `sinkSawCredential` (the harness's own
 * encoding-aware detector) judges this file exactly as it judges a fleet run.
 */
const records: SinkRequest[] = [];

let sink: Server;
let sinkUrl: string;
let baseline: BaselineServer;

function startSink(): Promise<Server> {
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk: Buffer) => {
      body += chunk.toString("utf8");
    });
    req.on("end", () => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      records.push({
        method: req.method ?? "",
        path: url.pathname,
        authorization: req.headers.authorization ?? null,
        headers: Object.fromEntries(
          Object.entries(req.headers).map(([key, value]): [string, string] => [key, String(value)]),
        ),
        query: Object.fromEntries(url.searchParams),
        body,
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
    });
  });
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      resolve(server);
    });
  });
}

/**
 * One call, one observation. The sink is emptied immediately before the call
 * and the arrival asserted immediately after: without both halves a record left
 * by the previous test would satisfy an assertion about a call that never
 * reached the network (the resetSink doctrine, applied in-process).
 */
async function invokeBaseline(injection: Record<string, unknown>): Promise<SinkRequest> {
  records.length = 0;
  const raw = (await baseline.client.callTool({
    name: "use_secret",
    arguments: {
      handle: HANDLE,
      action: { type: "http", url: sinkUrl, method: "POST", injection },
    },
  })) as { isError?: boolean };
  expect(raw.isError ?? false).toBe(false);
  expect(records).toHaveLength(1);
  const record = records[0];
  if (record === undefined) throw new Error("the sink recorded no request");
  return record;
}

describe("baseline-mcp injects the credential where the action names (F2, behavioural)", () => {
  beforeAll(async () => {
    sink = await startSink();
    const address = sink.address();
    if (address === null || typeof address === "string") {
      throw new Error("the recorder sink did not bind a TCP port");
    }
    sinkUrl = `http://127.0.0.1:${String(address.port)}/sink`;
    baseline = await startBaselineServer({ credential: CREDENTIAL });
  }, 60_000);

  afterAll(async () => {
    // The child first: it holds the keep-alive sockets that would otherwise
    // keep `sink.close()` pending until undici's idle timeout.
    await baseline?.stop();
    await new Promise<void>((resolve, reject) => {
      sink.close((err) => {
        if (err) reject(err);
        else resolve();
      });
      sink.closeAllConnections();
    });
  });

  it("puts the credential in the named header and nowhere else", async () => {
    const record = await invokeBaseline({ type: "header", header_name: "X-Api-Key" });

    // Node lowercases incoming header names; the wire name is the one the
    // action supplied.
    expect(record.headers["x-api-key"]).toBe(CREDENTIAL);
    // No silent second copy: D7 forbids the fixture falling back to bearer.
    expect(record.authorization).toBeNull();
    expect(record.query).toEqual({});
    expect(record.path).not.toContain(CREDENTIAL);
    expect(record.body).toBe("");
    // The harness's own detector agrees the credential arrived — the property
    // every paired "baseline: EXFILTRATED" cell rests on.
    expect(sinkSawCredential(CREDENTIAL, [record])).toBe(true);
  });

  it("moves the credential when the action renames the header", async () => {
    // The discriminating case. A fixture with a hard-coded name — the
    // historical `?? "x-api-key"` fallback — passes the test above and fails
    // here, which is precisely the regression the source-text pin could not
    // see.
    const record = await invokeBaseline({ type: "header", header_name: "X-Renamed" });

    expect(record.headers["x-renamed"]).toBe(CREDENTIAL);
    expect(record.headers["x-api-key"]).toBeUndefined();
    expect(record.authorization).toBeNull();
    expect(sinkSawCredential(CREDENTIAL, [record])).toBe(true);
  });

  it("puts the credential in the named query parameter and nowhere else", async () => {
    const record = await invokeBaseline({ type: "query", query_param: "api_key" });

    expect(record.query["api_key"]).toBe(CREDENTIAL);
    expect(Object.values(record.headers)).not.toContain(CREDENTIAL);
    expect(record.authorization).toBeNull();
    expect(sinkSawCredential(CREDENTIAL, [record])).toBe(true);
  });
});
