import type { IncomingMessage } from "node:http";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import type { VaultError } from "@harpoc/shared";
import { expectAbsent } from "@harpoc/test-utils";
import type { EgressProxy, EgressProxyOptions } from "./proxy.js";
import { createEgressProxy } from "./proxy.js";
import { SECRET_VALUE, TOKENS, engineDouble } from "./__fixtures__/engine-double.js";
import type { EngineDouble } from "./__fixtures__/engine-double.js";
import { proxyStream } from "./__fixtures__/proxy-client.js";
import type { ProxyStreamReply } from "./__fixtures__/proxy-client.js";
import { holdResponse, startUpstream } from "./__fixtures__/upstream-server.js";
import type { HeldResponse, UpstreamFixture } from "./__fixtures__/upstream-server.js";

const IDLE_LIMIT_MS = 1_500;
const SHORT_SILENCE_MS = 700;
const STEPPED_ROW_BUDGET_MS = 5_000;
const MARKER = "[REDACTED]";
const EVENT_STREAM = { "content-type": "text/event-stream" };

const PING = ": ping keep-alive.\n\n";
const EVENTS = [
  'event: message_start\ndata: {"id":"msg_1"}\n\n',
  'event: delta\ndata: {"text":"Hel"}\n\n',
  PING,
  'event: delta\ndata: {"text":"lo"}\n\n',
  'event: message_delta\ndata: {"stop_reason":"end_turn"}\n\n',
  "event: message_stop\ndata: {}\n\n",
] as const;

const ECHO_TAIL = '"}\n\n';
const REDACTED_ECHO = `event: echo\ndata: {"authorization":"Bearer ${MARKER}${ECHO_TAIL}`;

const BROKERED = {
  "proxy-authorization": `Bearer ${TOKENS.use}`,
  authorization: "Bearer harpoc:gh-pat",
  accept: "text/event-stream",
};

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
  upstream.seen.length = 0;
  double = engineDouble();
  reported = [];
  proxy = createEgressProxy({
    engine: double.engine,
    onError: (err, status) => reported.push([err, status]),
    ...extra,
  });
  port = (await proxy.listenTcp(0, "127.0.0.1")).port;
}

afterEach(async () => {
  await proxy.close();
});

/** The upstream's event that echoes the `Authorization` it was sent. */
function echoEvent(req: IncomingMessage): string {
  return `event: echo\ndata: {"authorization":"${req.headers.authorization ?? ""}${ECHO_TAIL}`;
}

interface EventReply extends ProxyStreamReply {
  /** Each event, its blank line included, in the order its blank line arrived. */
  events: string[];
}

/**
 * A brokered GET of the upstream's stream through the proxy: records each
 * event as its blank line arrives and hands `onEvent` the number arrived so far.
 */
async function readEvents(
  onEvent: (arrived: number) => void,
  deadlineMs?: number,
): Promise<EventReply> {
  const events: string[] = [];
  let pending = "";
  const reply = await proxyStream(
    { port, path: `/127.0.0.1:${upstream.port}/v1/messages`, headers: BROKERED },
    (chunk) => {
      pending += chunk;
      for (let end = pending.indexOf("\n\n"); end !== -1; end = pending.indexOf("\n\n")) {
        events.push(pending.slice(0, end + 2));
        pending = pending.slice(end + 2);
        onEvent(events.length);
      }
    },
    deadlineMs,
  );
  return { ...reply, events };
}

/** The upstream's move once the client holds `arrived` of `events`: the next one, or the end. */
function sendNext(stream: HeldResponse, events: readonly string[], arrived: number): void {
  const next = events[arrived];
  if (next === undefined) stream.end();
  else stream.write(next);
}

describe("a text/event-stream response through a brokered request", () => {
  beforeEach(async () => {
    await startProxy();
  });

  it("each event arrives when it is sent: the upstream writes the next only once the client holds the one before; six events, a 20-byte ping among them, all arrive and the body ends", async () => {
    const stream = holdResponse(upstream, EVENT_STREAM, () => EVENTS[0]);

    const reply = await readEvents(
      (arrived) => sendNext(stream, EVENTS, arrived),
      STEPPED_ROW_BUDGET_MS,
    );
    await proxy.close();

    expect(reply.status).toBe(200);
    expect(reply.headers["content-type"]).toBe("text/event-stream");
    expect(reply.events).toEqual(EVENTS);
    expect(reply.body).toBe(EVENTS.join(""));
    expect(reply.complete).toBe(true);
    expect(double.leases[0]?.complete.mock.calls).toEqual([[{ status: 200, sanitized: false }]]);
    expect(reported).toEqual([]);
  });

  it("an event that holds the value arrives with the marker in its place and nothing held back; the lease's outcome is sanitized", async () => {
    const stream = holdResponse(upstream, EVENT_STREAM, echoEvent);

    const reply = await readEvents(() => stream.end());
    await proxy.close();

    expectAbsent(reply.body, SECRET_VALUE, "the client's bytes");
    expect(upstream.seen[0]?.headers.authorization).toBe(`Bearer ${SECRET_VALUE}`);
    expect(reply.events).toEqual([REDACTED_ECHO]);
    expect(reply.body).toBe(REDACTED_ECHO);
    expect(reply.complete).toBe(true);
    expect(double.leases[0]?.complete.mock.calls).toEqual([[{ status: 200, sanitized: true }]]);
    expect(reported).toEqual([]);
  });

  it("the value split across two writes inside one event is redacted, and the event arrives with the write that completes its blank line", async () => {
    let rest = "";
    const stream = holdResponse(upstream, EVENT_STREAM, (req) => {
      const echo = echoEvent(req);
      const split = echo.length - ECHO_TAIL.length - SECRET_VALUE.length / 2;
      rest = echo.slice(split);
      return `${EVENTS[0]}${echo.slice(0, split)}`;
    });

    const reply = await readEvents((arrived) => {
      if (arrived === 1) stream.write(rest);
      else stream.end();
    });
    await proxy.close();

    expectAbsent(reply.body, SECRET_VALUE, "the client's bytes");
    expect(upstream.seen[0]?.headers.authorization).toBe(`Bearer ${SECRET_VALUE}`);
    expect(reply.events).toEqual([EVENTS[0], REDACTED_ECHO]);
    expect(reply.body).toBe(`${EVENTS[0]}${REDACTED_ECHO}`);
    expect(reply.complete).toBe(true);
    expect(double.leases[0]?.complete.mock.calls).toEqual([[{ status: 200, sanitized: true }]]);
    expect(reported).toEqual([]);
  });
});

describe("the idle limit on a brokered event stream (bodyIdleTimeoutMs: 1_500)", () => {
  beforeEach(async () => {
    await startProxy({ bodyIdleTimeoutMs: IDLE_LIMIT_MS });
  });

  it("a silence of 700 ms is survived: the event after it arrives and the body ends", async () => {
    const stream = holdResponse(upstream, EVENT_STREAM, () => EVENTS[0]);

    const reply = await readEvents((arrived) => {
      if (arrived === 1) setTimeout(() => stream.write(EVENTS[1]), SHORT_SILENCE_MS);
      else stream.end();
    });
    await proxy.close();

    expect(reply.events).toEqual([EVENTS[0], EVENTS[1]]);
    expect(reply.complete).toBe(true);
    expect(reply.elapsedMs).toBeGreaterThanOrEqual(SHORT_SILENCE_MS);
    expect(double.leases[0]?.complete.mock.calls).toEqual([[{ status: 200, sanitized: false }]]);
    expect(reported).toEqual([]);
  });

  it("a silence past the limit ends the stream no sooner than the limit: the client holds every event sent before it whole, the lease completes failed with the status it began with, onError hears of it once", async () => {
    const sent = EVENTS.slice(0, 3);
    const stream = holdResponse(upstream, EVENT_STREAM, () => EVENTS[0]);

    const reply = await readEvents((arrived) => {
      const next = sent[arrived];
      if (next !== undefined) stream.write(next);
    });
    await proxy.close();

    expect(reply.status).toBe(200);
    expect(reply.events).toEqual(sent);
    expect(reply.body).toBe(sent.join(""));
    expect(reply.complete).toBe(false);
    expect(reply.elapsedMs).toBeGreaterThanOrEqual(IDLE_LIMIT_MS);
    expect(double.leases[0]?.complete.mock.calls).toEqual([
      [{ status: 200, error: ErrorCode.PROXY_UPSTREAM_FAILED, sanitized: false }],
    ]);
    expect(reported.map(([err, status]) => [err.code, err.message, status])).toEqual([
      [
        ErrorCode.PROXY_UPSTREAM_FAILED,
        `Egress proxy upstream request failed (timeout): ${upstream.origin}`,
        502,
      ],
    ]);
  });
});
