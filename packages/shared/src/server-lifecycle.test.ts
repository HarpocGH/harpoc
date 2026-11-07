import { describe, expect, it } from "vitest";
import { SERVER_STOP_TRIGGERS, SERVER_TRANSPORTS } from "./server-lifecycle.js";
import type { ServerStopTrigger, ServerTransport } from "./server-lifecycle.js";

describe("server-lifecycle", () => {
  it("names exactly the five listener transports (the egress proxy since B2, the agent socket since B3)", () => {
    expect([...SERVER_TRANSPORTS]).toEqual(["stdio", "http", "rest", "proxy", "ssh-agent"]);
  });

  it("names exactly the three stop triggers", () => {
    expect([...SERVER_STOP_TRIGGERS]).toEqual(["SIGINT", "SIGTERM", "transport_closed"]);
  });

  it("derives unions that admit no member the tuples do not carry", () => {
    // @ts-expect-error "smtp" is not a listener transport
    const transport: ServerTransport = "smtp";
    // @ts-expect-error "SIGHUP" is not a stop trigger
    const trigger: ServerStopTrigger = "SIGHUP";
    expect([transport, trigger]).toEqual(["smtp", "SIGHUP"]);
  });
});
