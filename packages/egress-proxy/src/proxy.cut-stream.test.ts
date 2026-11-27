import { Server, request } from "node:http";
import type { ClientRequest, IncomingMessage, ServerResponse } from "node:http";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import type { VaultError } from "@harpoc/shared";
import { expectAbsent } from "@harpoc/test-utils";
import type { EgressProxy, EgressProxyOptions } from "./proxy.js";
import { createEgressProxy } from "./proxy.js";
import {
  SECRET_VALUE,
  TOKENS,
  engineDouble,
  recordingLease,
} from "./__fixtures__/engine-double.js";
import type { EngineDouble } from "./__fixtures__/engine-double.js";
import { PROXY_CLIENT_TIMEOUT_MS } from "./__fixtures__/proxy-client.js";
import {
  CAN_SET_DEFAULT_CA,
  startUpstream,
  trustFixtureCaByDefault,
} from "./__fixtures__/upstream-server.js";
import type { UpstreamFixture } from "./__fixtures__/upstream-server.js";

const IDLE_LIMIT_MS = 1_000;
const FIRST_CHUNK = "data: one\n\n";
const MARKER = "[REDACTED]";
const ORIGIN_HOST_VALUE = "127.0.0.1";

let upstream: UpstreamFixture;
let double: EngineDouble;
let proxy: EgressProxy;
let port: number;
let reported: [VaultError, number][];

beforeAll(async () => {
  upstream = await startUpstream();
});

afterAll(async () => {
  await upstream.close();
});

async function startProxy(extra: Partial<EgressProxyOptions> = {}): Promise<void> {
  double = engineDouble();
  reported = [];
  proxy = createEgressProxy({
    engine: double.engine,
    onError: (err, status) => reported.push([err, status]),
    ...extra,
  });
  port = (await proxy.listenTcp(0, "127.0.0.1")).port;
}

beforeEach(async () => {
  upstream.seen.length = 0;
  await startProxy();
});

afterEach(async () => {
  await proxy.close();
});

const BROKERED = {
  "proxy-authorization": `Bearer ${TOKENS.use}`,
  authorization: "Bearer harpoc:gh-pat",
};
const PASS_THROUGH = { "proxy-authorization": `Bearer ${TOKENS.use}` };

/**
 * The upstream sends its head and a first chunk, then holds the response open
 * and silent; `cut()` destroys its socket.
 */
function holdAfterFirstChunk(first: (req: IncomingMessage) => string = () => FIRST_CHUNK): {
  cut: () => void;
} {
  let held: ServerResponse | undefined;
  upstream.script((req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.write(first(req));
    held = res;
  });
  return { cut: () => held?.socket?.destroy() };
}

interface StreamReply {
  status: number;
  body: string;
  /** Node's `IncomingMessage.complete`: the response's terminating chunk arrived. */
  complete: boolean;
  /** From the request's start to the response's close. */
  elapsedMs: number;
}

/**
 * One GET to the upstream fixture through the proxy over `node:http`, keep-alive
 * off, with a deadline; `onFirstChunk` runs at the first body bytes. Resolves
 * when the response closes, whole or cut.
 */
function streamThroughProxy(
  headers: Record<string, string>,
  onFirstChunk?: (req: ClientRequest) => void,
): Promise<StreamReply> {
  return new Promise((resolve, reject) => {
    const started = performance.now();
    const req = request(
      {
        host: "127.0.0.1",
        port,
        path: `/127.0.0.1:${upstream.port}/stream`,
        headers,
        agent: false,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => {
          if (chunks.length === 0) onFirstChunk?.(req);
          chunks.push(chunk);
        });
        res.on("error", () => undefined);
        res.on("close", () =>
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
            complete: res.complete,
            elapsedMs: performance.now() - started,
          }),
        );
      },
    );
    req.setTimeout(PROXY_CLIENT_TIMEOUT_MS, () => {
      reject(new Error("the streamed request outlived its deadline"));
      req.destroy();
    });
    req.on("error", (err) => {
      if ((err as NodeJS.ErrnoException).code !== "ECONNRESET") reject(err);
    });
    req.end();
  });
}

function reportedAs(): [string, number][] {
  return reported.map(([err, status]) => [err.code, status]);
}

describe("a brokered body the upstream cuts after its head", () => {
  it("silent past bodyIdleTimeoutMs: the client's response ends without its terminating chunk, the lease completes failed with the status it began with, onError hears of it once", async () => {
    await proxy.close();
    await startProxy({ bodyIdleTimeoutMs: IDLE_LIMIT_MS });
    holdAfterFirstChunk();

    const reply = await streamThroughProxy(BROKERED);
    await proxy.close();

    expect(reply.status).toBe(200);
    expect(reply.body).toBe(FIRST_CHUNK);
    expect(reply.complete).toBe(false);
    expect(reply.elapsedMs).toBeGreaterThanOrEqual(IDLE_LIMIT_MS);
    expect(double.leases[0]?.complete.mock.calls).toEqual([
      [{ status: 200, error: "PROXY_UPSTREAM_FAILED", sanitized: false }],
    ]);
    expect(reported.map(([err, status]) => [err.code, err.message, status])).toEqual([
      [
        ErrorCode.PROXY_UPSTREAM_FAILED,
        `Egress proxy upstream request failed (timeout): ${upstream.origin}`,
        502,
      ],
    ]);
  });

  it("its socket destroyed mid-body: the same outcome, onError once", async () => {
    const upstreamSide = holdAfterFirstChunk();

    const reply = await streamThroughProxy(BROKERED, () => upstreamSide.cut());
    await proxy.close();

    expect(reply.status).toBe(200);
    expect(reply.body).toBe(FIRST_CHUNK);
    expect(reply.complete).toBe(false);
    expect(double.leases[0]?.complete.mock.calls).toEqual([
      [{ status: 200, error: "PROXY_UPSTREAM_FAILED", sanitized: false }],
    ]);
    expect(reportedAs()).toEqual([[ErrorCode.PROXY_UPSTREAM_FAILED, 502]]);
  });

  it.each([
    ["the value", SECRET_VALUE],
    ["a value the upstream's origin spells", ORIGIN_HOST_VALUE],
  ])(
    "no client byte, outcome field or onError text holds %s; the redaction before the cut marks the row sanitized",
    async (_title, value) => {
      const lease = recordingLease(value);
      double.resolveForProxy.mockResolvedValueOnce(lease);
      const upstreamSide = holdAfterFirstChunk((req) => `${req.headers.authorization ?? ""}\n`);

      const reply = await streamThroughProxy(BROKERED, () => upstreamSide.cut());
      await proxy.close();

      expectAbsent(reply.body, value, "the client's bytes");
      for (const [err] of reported) expectAbsent(err.message, value, "an onError message");
      expect(reply.body).toBe(`Bearer ${MARKER}\n`);
      expect(upstream.seen[0]?.headers.authorization).toBe(`Bearer ${value}`);
      expect(lease.complete.mock.calls).toEqual([
        [{ status: 200, error: "PROXY_UPSTREAM_FAILED", sanitized: true }],
      ]);
      expect(reportedAs()).toEqual([[ErrorCode.PROXY_UPSTREAM_FAILED, 502]]);
    },
  );
});

describe.skipIf(!CAN_SET_DEFAULT_CA)(
  "a pass-through body the upstream cuts after its head (the fixture CA trusted by default)",
  () => {
    let restore: () => void;

    beforeAll(() => {
      restore = trustFixtureCaByDefault();
    });

    afterAll(() => {
      restore();
    });

    it("onError hears of it once; no lease", async () => {
      const upstreamSide = holdAfterFirstChunk();

      const reply = await streamThroughProxy(PASS_THROUGH, () => upstreamSide.cut());
      await proxy.close();

      expect(reply.status).toBe(200);
      expect(reply.body).toBe(FIRST_CHUNK);
      expect(reply.complete).toBe(false);
      expect(double.resolveForProxy).not.toHaveBeenCalled();
      expect(reportedAs()).toEqual([[ErrorCode.PROXY_UPSTREAM_FAILED, 502]]);
    });
  },
);

describe("a body the upstream does not cut keeps today's outcome", () => {
  it("the client hangs up mid-body: the lease completes { status: 200, sanitized: false }, onError is not called", async () => {
    holdAfterFirstChunk();

    const reply = await streamThroughProxy(BROKERED, (req) => req.destroy());
    await vi.waitFor(() => expect(double.leases[0]?.complete).toHaveBeenCalled());
    await proxy.close();

    expect(reply.body).toBe(FIRST_CHUNK);
    expect(double.leases[0]?.complete.mock.calls).toEqual([[{ status: 200, sanitized: false }]]);
    expect(reported).toEqual([]);
  });

  it("close() mid-body: the lease completes { status: 200, sanitized: false }, onError is not called", async () => {
    holdAfterFirstChunk();
    let firstChunk: () => void = () => undefined;
    const arrived = new Promise<void>((resolve) => {
      firstChunk = resolve;
    });

    const replying = streamThroughProxy(BROKERED, () => firstChunk());
    await arrived;
    await proxy.close();
    const reply = await replying;

    expect(reply.body).toBe(FIRST_CHUNK);
    expect(reply.complete).toBe(false);
    expect(double.leases[0]?.complete.mock.calls).toEqual([[{ status: 200, sanitized: false }]]);
    expect(reported).toEqual([]);
  });

  it("close() whose end of the upstream reaches the body before the client's connection closes: the same outcome, onError is not called", async () => {
    holdAfterFirstChunk();
    const lease = recordingLease();
    double.resolveForProxy.mockResolvedValueOnce(lease);
    const closeAll = Server.prototype.closeAllConnections;
    let deferred: () => void = () => undefined;
    const held = vi.spyOn(Server.prototype, "closeAllConnections").mockImplementation(function (
      this: Server,
    ) {
      deferred = () => closeAll.call(this);
    });
    lease.complete.mockImplementation(() => deferred());
    let firstChunk: () => void = () => undefined;
    const arrived = new Promise<void>((resolve) => {
      firstChunk = resolve;
    });

    try {
      const replying = streamThroughProxy(BROKERED, () => firstChunk());
      await arrived;
      await proxy.close();
      await replying;
    } finally {
      held.mockRestore();
    }

    expect(lease.complete.mock.calls).toEqual([[{ status: 200, sanitized: false }]]);
    expect(reported).toEqual([]);
  });
});
