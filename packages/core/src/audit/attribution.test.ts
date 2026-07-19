import { describe, expect, it } from "vitest";
import type { CallerContext } from "@harpoc/shared";
import { attributionFromCaller, callerInterfaceDetail, withAttribution } from "./attribution.js";
import type { AuditLogOptions } from "./audit-logger.js";

const CALLER: CallerContext = {
  principal_type: "agent",
  principal_id: "alice",
  interface: "rest",
};

describe("attributionFromCaller", () => {
  it("returns undefined when caller and session are both absent (trusted local, no session)", () => {
    expect(attributionFromCaller(undefined, null)).toBeUndefined();
    expect(attributionFromCaller(undefined, undefined)).toBeUndefined();
  });

  it("carries the principal, interface and session when all are present", () => {
    expect(attributionFromCaller(CALLER, "sess-1")).toEqual({
      principal_type: "agent",
      principal_id: "alice",
      interface: "rest",
      session_id: "sess-1",
    });
  });

  it("session-only for the trusted local path — rows stay session-attributed, never principal-attributed", () => {
    expect(attributionFromCaller(undefined, "sess-1")).toEqual({ session_id: "sess-1" });
  });

  it("omits the interface when the caller carries none", () => {
    const attribution = attributionFromCaller(
      { principal_type: "tool", principal_id: "ci" },
      "sess-1",
    );
    expect(attribution).toEqual({
      principal_type: "tool",
      principal_id: "ci",
      session_id: "sess-1",
    });
    expect(attribution && "interface" in attribution).toBe(false);
  });
});

describe("withAttribution", () => {
  const base = (): AuditLogOptions => ({
    eventType: "secret.use",
    secretId: "s-1",
    detail: { context: "process" },
    success: true,
  });

  it("returns the options untouched when there is no attribution", () => {
    const options = base();
    const merged = withAttribution(options, undefined);
    expect(merged).toBe(options);
    expect(merged.principalType).toBeUndefined();
    expect(merged.principalId).toBeUndefined();
    expect(merged.sessionId).toBeUndefined();
  });

  it("stamps principal and session as columns and the interface into detail", () => {
    const merged = withAttribution(base(), {
      principal_type: "agent",
      principal_id: "alice",
      session_id: "sess-1",
      interface: "mcp-http",
    });
    expect(merged.principalType).toBe("agent");
    expect(merged.principalId).toBe("alice");
    expect(merged.sessionId).toBe("sess-1");
    expect(merged.detail).toEqual({ context: "process", interface: "mcp-http" });
  });

  it("preserves the existing detail keys when merging the interface", () => {
    const merged = withAttribution(
      { eventType: "secret.use", detail: { a: 1, b: "x" } },
      { interface: "rest" },
    );
    expect(merged.detail).toEqual({ a: 1, b: "x", interface: "rest" });
  });

  it("creates a detail carrying only the interface when the entry had none", () => {
    const merged = withAttribution({ eventType: "secret.use" }, { interface: "mcp" });
    expect(merged.detail).toEqual({ interface: "mcp" });
  });

  it("leaves detail untouched for an interface-less attribution (local session)", () => {
    const merged = withAttribution(base(), { session_id: "sess-1" });
    expect(merged.sessionId).toBe("sess-1");
    expect(merged.detail).toEqual({ context: "process" });
    expect(merged.principalType).toBeUndefined();
  });
});

describe("callerInterfaceDetail", () => {
  it("is empty for an absent caller and for a caller without an interface", () => {
    expect(callerInterfaceDetail(undefined)).toEqual({});
    expect(callerInterfaceDetail({ principal_type: "agent", principal_id: "a" })).toEqual({});
  });

  it("carries the interface when set", () => {
    expect(callerInterfaceDetail(CALLER)).toEqual({ interface: "rest" });
  });
});
